use std::{
    fmt,
    fmt::Write as _,
    sync::{Arc, Mutex, PoisonError, atomic::AtomicU64},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use automata_ci_core::JobLifecycle;
use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox,
    ExecutionCommand, ExecutionEndpoint, ExecutionError, ExecutionErrorKind, ExecutionOutput,
    ExecutionStage, ExecutionTermination, ProviderCapabilities, ProviderError, ProviderErrorKind,
    ProviderId, ProviderStage, SandboxCapability, SandboxHandle, SandboxInspection,
    SandboxProvider, SandboxRecord, SandboxSpec, ServiceContainerBindings, SignalRequest,
    WaitRequest,
};
use automata_ci_metrics::{
    BuildInfo as MetricsBuildInfo, BuildInfoError, Counter, ExporterLimits, Family, Gauge,
    Histogram, Metrics, MetricsBuilder, ProcessMetricsSampler, ProcessRole, Registry, Unit,
    classic_and_native_histogram,
};
use automata_ci_protocol::RunnerToServer;
use automata_ci_runner_journal::{
    FileJournal, JournalError, JournalMutationDomain, JournalMutationObservation,
    JournalMutationOutcome, JournalObserver, JournalSnapshot, LeaseOfferStatus, MAX_JOURNAL_BYTES,
    MAX_JOURNALED_SLOTS, OrphanDelivery, RunnerJournal,
};
use automata_ci_runner_runtime::{
    RunnerRuntimeEvent, RunnerRuntimeObserver, RuntimeCancellationReason, RuntimeCommandKind,
    RuntimeCommandOutcome, RuntimeExchangeKind, RuntimeInfrastructureFailure, RuntimeJobConclusion,
    RuntimeJobStartMode, RuntimeLeaseDisposition, RuntimeLeasePollOutcome, RuntimeOperationOutcome,
    RuntimeReconnectReason, RuntimeRemoteErrorDisposition, RuntimeRemoteErrorKind,
    RuntimeRetryCause, RuntimeSessionMode, RuntimeSessionOutcome, RuntimeTerminalResultStage,
};
use automata_ci_runner_spool::{
    ContentKind, FileSpool, SpoolCapacityResource, SpoolError, SpoolEvent, SpoolFailureKind,
    SpoolObserver, SpoolOperation, SpoolOperationOutcome, SpoolProtectionOperation,
    SpoolProtectionOutcome,
};
use automata_ci_runner_transport::{
    ClientErrorKind, ClientFuture, PreparedRequest, RetryClass, RunnerControlClient,
    RunnerControlClientByteDirection, RunnerControlClientObserver,
};
use automata_ci_sandbox_podman::{
    DockerProxyOutcome, DockerProxyRejection, DockerProxyRoute, PodmanCommandOutcome,
    PodmanCommandStage, PodmanEvent, PodmanObserver,
};
use prometheus_client::{
    collector::Collector,
    encoding::{
        DescriptorEncoder, EncodeLabelSet, EncodeLabelValue, EncodeMetric, LabelValueEncoder,
    },
    metrics::{MetricType, gauge::ConstGauge},
};
use tokio_util::sync::CancellationToken;

use crate::build_info::BuildInfo;

use super::resource_metrics::ResourceMetricsSampler;

const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5);
type FloatGauge = prometheus_client::metrics::gauge::Gauge<f64, AtomicU64>;

/// Product-owned runner metrics and the sole registry exporter for this process.
#[derive(Clone)]
pub(super) struct RunnerMetrics {
    exporter: Metrics,
    process_sampler: ProcessMetricsSampler,
    resource_sampler: ResourceMetricsSampler,
    ready: Gauge,
    control: ControlMetrics,
    semantic: SemanticMetrics,
    journal_operations: JournalMetrics,
    spool_operations: SpoolMetrics,
    sandbox: SandboxMetrics,
    podman: PodmanMetrics,
    snapshot: SnapshotMetrics,
}

impl fmt::Debug for RunnerMetrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerMetrics")
            .finish_non_exhaustive()
    }
}

impl RunnerMetrics {
    pub(super) fn new(
        configured_slots: u16,
        runner_cgroup: Option<String>,
    ) -> Result<Self, BuildInfoError> {
        let build = BuildInfo::current();
        let mut builder = MetricsBuilder::new(MetricsBuildInfo::new(
            ProcessRole::Runner,
            build.version,
            build.commit,
        ))?;
        let registry = builder.registry_mut();

        let ready = register_gauge(
            registry,
            "runner_ready",
            "Whether runner composition is complete and its supervisor is active",
        );
        let control = ControlMetrics::register(registry);
        let semantic = SemanticMetrics::register(registry);
        let journal_operations = JournalMetrics::register(registry);
        let spool_operations = SpoolMetrics::register(registry);
        let sandbox = SandboxMetrics::register(registry);
        let podman = PodmanMetrics::register(registry);
        let snapshot = SnapshotMetrics::register(registry, configured_slots);
        let resource_sampler = ResourceMetricsSampler::register(registry, runner_cgroup);
        let process_sampler = builder.process_sampler();
        let exporter = builder.finish(ExporterLimits::default());

        Ok(Self {
            exporter,
            process_sampler,
            resource_sampler,
            ready,
            control,
            semantic,
            journal_operations,
            spool_operations,
            sandbox,
            podman,
            snapshot,
        })
    }

    pub(super) fn exporter(&self) -> Metrics {
        self.exporter.clone()
    }

    pub(super) fn set_ready(&self, ready: bool) {
        self.ready.set(i64::from(ready));
        if !ready {
            self.semantic.session_connected.set(0);
        }
    }

    pub(super) fn runtime_observer(&self) -> Arc<dyn RunnerRuntimeObserver> {
        Arc::new(self.clone())
    }

    pub(super) fn spool_observer(&self) -> Arc<dyn SpoolObserver> {
        Arc::new(self.clone())
    }

    pub(super) fn journal_observer(&self) -> Arc<dyn JournalObserver> {
        Arc::new(self.clone())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn podman_observer(&self) -> Arc<dyn PodmanObserver> {
        Arc::new(self.clone())
    }

    pub(super) fn instrument_sandbox_provider(
        &self,
        inner: Arc<dyn SandboxProvider>,
    ) -> Arc<dyn SandboxProvider> {
        Arc::new(ObservedSandboxProvider {
            inner,
            metrics: self.sandbox.clone(),
        })
    }

    pub(super) fn instrument_control(
        &self,
        inner: Arc<dyn RunnerControlClient>,
    ) -> Arc<dyn RunnerControlClient> {
        Arc::new(ObservedRunnerControlClient {
            inner,
            metrics: self.control.clone(),
        })
    }

    pub(super) fn control_transport_observer(&self) -> Arc<dyn RunnerControlClientObserver> {
        Arc::new(ControlTransportObserver {
            metrics: self.control.clone(),
        })
    }

    pub(super) fn refresh(&self, journal: &FileJournal, spool: &FileSpool) {
        self.snapshot.refresh(journal, spool);
    }

    pub(super) async fn sample_until_cancelled(
        self,
        journal: Arc<FileJournal>,
        spool: Arc<FileSpool>,
        shutdown: CancellationToken,
    ) {
        let process_sampler = self.process_sampler.clone();
        let process_sampling =
            process_sampler.run_until_cancelled(shutdown.clone().cancelled_owned());
        let resource_sampling = self
            .resource_sampler
            .clone()
            .run_until_cancelled(shutdown.clone());
        tokio::pin!(process_sampling);
        tokio::pin!(resource_sampling);
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    (&mut process_sampling).await;
                    (&mut resource_sampling).await;
                    return;
                },
                () = &mut process_sampling => return,
                () = &mut resource_sampling => return,
                () = tokio::time::sleep(SNAPSHOT_INTERVAL) => self.refresh(&journal, &spool),
            }
        }
    }
}

fn register_gauge(registry: &mut Registry, name: &'static str, help: &'static str) -> Gauge {
    let metric = Gauge::default();
    registry.register(name, help, metric.clone());
    metric
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct JournalMutationLabels {
    domain: &'static str,
    outcome: &'static str,
}

const fn journal_domain_label(domain: JournalMutationDomain) -> &'static str {
    match domain {
        JournalMutationDomain::Session => "session",
        JournalMutationDomain::LeasePoll => "lease_poll",
        JournalMutationDomain::Command => "command",
        JournalMutationDomain::Lease => "lease",
        JournalMutationDomain::Lifecycle => "lifecycle",
        JournalMutationDomain::Result => "result",
        JournalMutationDomain::Provider => "provider",
        JournalMutationDomain::Outbound => "outbound",
        JournalMutationDomain::Log => "log",
        JournalMutationDomain::Orphan => "orphan",
        JournalMutationDomain::Slot => "slot",
    }
}

const fn journal_outcome_label(outcome: JournalMutationOutcome) -> &'static str {
    match outcome {
        JournalMutationOutcome::Committed => "committed",
        JournalMutationOutcome::Noop => "noop",
        JournalMutationOutcome::Rejected => "rejected",
        JournalMutationOutcome::IoError => "io_error",
        JournalMutationOutcome::Uncertain => "uncertain",
        JournalMutationOutcome::Poisoned => "poisoned",
    }
}

#[derive(Clone)]
struct JournalMetrics {
    mutations: Family<JournalMutationLabels, Counter>,
    duration: Histogram,
    size_bytes: Gauge,
}

impl JournalMetrics {
    fn register(registry: &mut Registry) -> Self {
        let mutations = Family::<JournalMutationLabels, Counter>::default();
        registry.register(
            "runner_journal_mutations",
            "Physical journal mutation attempts by finite durable domain and terminal outcome",
            mutations.clone(),
        );
        let duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_journal_mutation_duration",
            "Physical journal mutation duration across all durable domains and outcomes",
            Unit::Seconds,
            duration.clone(),
        );
        let size_bytes = Gauge::default();
        registry.register_with_unit(
            "runner_journal_size",
            "Canonical encoded journal bytes at the latest successful open or commit",
            Unit::Bytes,
            size_bytes.clone(),
        );
        let metrics = Self {
            mutations,
            duration,
            size_bytes,
        };
        metrics.preinitialize();
        metrics
    }

    fn preinitialize(&self) {
        for domain in [
            "session",
            "lease_poll",
            "command",
            "lease",
            "lifecycle",
            "result",
            "provider",
            "outbound",
            "log",
            "orphan",
            "slot",
        ] {
            for outcome in [
                "committed",
                "noop",
                "rejected",
                "io_error",
                "uncertain",
                "poisoned",
            ] {
                self.mutations
                    .get_or_create(&JournalMutationLabels { domain, outcome })
                    .inc_by(0);
            }
        }
    }
}

impl JournalObserver for RunnerMetrics {
    fn observe_opened(&self, encoded_bytes: u64) {
        self.journal_operations
            .size_bytes
            .set(saturating_i64(encoded_bytes));
    }

    fn observe_mutation(&self, observation: JournalMutationObservation) {
        self.journal_operations
            .mutations
            .get_or_create(&JournalMutationLabels {
                domain: journal_domain_label(observation.domain()),
                outcome: journal_outcome_label(observation.outcome()),
            })
            .inc();
        self.journal_operations
            .duration
            .observe(observation.duration().as_secs_f64());
        if let Some(encoded_bytes) = observation.encoded_bytes() {
            self.journal_operations
                .size_bytes
                .set(saturating_i64(encoded_bytes));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ControlRequestKind {
    Handshake,
    LeaseRequest,
    LeaseResponse,
    RuntimeAuthorityRequest,
    RuntimeAuthorityAck,
    Heartbeat,
    JobState,
    JobResult,
    LogBatch,
    CommandAck,
}

impl ControlRequestKind {
    const ALL: [Self; 10] = [
        Self::Handshake,
        Self::LeaseRequest,
        Self::LeaseResponse,
        Self::RuntimeAuthorityRequest,
        Self::RuntimeAuthorityAck,
        Self::Heartbeat,
        Self::JobState,
        Self::JobResult,
        Self::LogBatch,
        Self::CommandAck,
    ];

    const fn from_request(request: &PreparedRequest) -> Self {
        match request.message() {
            RunnerToServer::Hello(_) => Self::Handshake,
            RunnerToServer::LeaseRequest(_) => Self::LeaseRequest,
            RunnerToServer::LeaseResponse(_) => Self::LeaseResponse,
            RunnerToServer::RuntimeAuthorityRequest(_) => Self::RuntimeAuthorityRequest,
            RunnerToServer::RuntimeAuthorityAck(_) => Self::RuntimeAuthorityAck,
            RunnerToServer::Heartbeat(_) => Self::Heartbeat,
            RunnerToServer::JobState(_) => Self::JobState,
            RunnerToServer::JobResult(_) => Self::JobResult,
            RunnerToServer::LogBatch(_) => Self::LogBatch,
            RunnerToServer::CommandAck(_) => Self::CommandAck,
        }
    }
}

impl EncodeLabelValue for ControlRequestKind {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        encoder.write_str(match self {
            Self::Handshake => "handshake",
            Self::LeaseRequest => "lease_request",
            Self::LeaseResponse => "lease_response",
            Self::RuntimeAuthorityRequest => "runtime_authority_request",
            Self::RuntimeAuthorityAck => "runtime_authority_ack",
            Self::Heartbeat => "heartbeat",
            Self::JobState => "job_state",
            Self::JobResult => "job_result",
            Self::LogBatch => "log_batch",
            Self::CommandAck => "command_ack",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ControlOutcome {
    Success,
    TransportError,
    Timeout,
    Cancelled,
    HttpError,
    InvalidResponse,
}

impl ControlOutcome {
    const ALL: [Self; 6] = [
        Self::Success,
        Self::TransportError,
        Self::Timeout,
        Self::Cancelled,
        Self::HttpError,
        Self::InvalidResponse,
    ];

    const fn from_error(kind: ClientErrorKind) -> Self {
        match kind {
            ClientErrorKind::Transport => Self::TransportError,
            ClientErrorKind::Timeout => Self::Timeout,
            ClientErrorKind::Cancelled => Self::Cancelled,
            ClientErrorKind::HttpStatus(_) => Self::HttpError,
            ClientErrorKind::InvalidResponse
            | ClientErrorKind::ResponseTooLarge
            | ClientErrorKind::InvalidProtobuf => Self::InvalidResponse,
        }
    }
}

impl EncodeLabelValue for ControlOutcome {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        encoder.write_str(match self {
            Self::Success => "success",
            Self::TransportError => "transport_error",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::HttpError => "http_error",
            Self::InvalidResponse => "invalid_response",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ControlRequestLabels {
    kind: ControlRequestKind,
    outcome: ControlOutcome,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ControlKindLabels {
    kind: ControlRequestKind,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ControlDirection {
    Sent,
    Received,
}

impl EncodeLabelValue for ControlDirection {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        encoder.write_str(match self {
            Self::Sent => "sent",
            Self::Received => "received",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ControlDirectionLabels {
    direction: ControlDirection,
}

type ControlDurationFamily = Family<ControlKindLabels, Histogram, fn() -> Histogram>;

fn control_duration_histogram() -> Histogram {
    classic_and_native_histogram([0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0])
}

#[derive(Clone)]
struct ControlMetrics {
    requests: Family<ControlRequestLabels, Counter>,
    duration: ControlDurationFamily,
    in_flight: Family<ControlKindLabels, Gauge>,
    retries: Family<ControlKindLabels, Counter>,
    bytes: Family<ControlDirectionLabels, Counter>,
    last_success_seconds: Gauge,
}

impl ControlMetrics {
    fn register(registry: &mut Registry) -> Self {
        let requests = Family::<ControlRequestLabels, Counter>::default();
        registry.register(
            "runner_control_requests",
            "Physical runner-control request attempts by finite message kind and outcome",
            requests.clone(),
        );
        let duration = Family::<ControlKindLabels, Histogram, _>::new_with_constructor(
            control_duration_histogram as fn() -> Histogram,
        );
        registry.register_with_unit(
            "runner_control_request_duration",
            "Physical runner-control request duration by finite message kind",
            Unit::Seconds,
            duration.clone(),
        );
        let in_flight = Family::<ControlKindLabels, Gauge>::default();
        registry.register(
            "runner_control_requests_in_flight",
            "Physical runner-control requests currently in flight",
            in_flight.clone(),
        );
        let retries = Family::<ControlKindLabels, Counter>::default();
        registry.register(
            "runner_control_retries",
            "Physical runner-control attempts repeating an identical retryable operation",
            retries.clone(),
        );
        let bytes = Family::<ControlDirectionLabels, Counter>::default();
        registry.register_with_unit(
            "runner_control",
            "Canonical request bytes dispatched to the runner-control transport and validated response bytes accepted",
            Unit::Bytes,
            bytes.clone(),
        );
        let last_success_seconds = Gauge::default();
        registry.register_with_unit(
            "runner_control_last_success_timestamp",
            "Unix timestamp of the last valid runner-control response",
            Unit::Seconds,
            last_success_seconds.clone(),
        );

        for kind in ControlRequestKind::ALL {
            let kind_labels = ControlKindLabels { kind };
            in_flight.get_or_create(&kind_labels).set(0);
            retries.get_or_create(&kind_labels).inc_by(0);
            let _ = duration.get_or_create(&kind_labels);
            for outcome in ControlOutcome::ALL {
                requests
                    .get_or_create(&ControlRequestLabels { kind, outcome })
                    .inc_by(0);
            }
        }
        for direction in [ControlDirection::Sent, ControlDirection::Received] {
            bytes
                .get_or_create(&ControlDirectionLabels { direction })
                .inc_by(0);
        }

        Self {
            requests,
            duration,
            in_flight,
            retries,
            bytes,
            last_success_seconds,
        }
    }

    fn begin(&self, kind: ControlRequestKind) -> ControlRequestGuard {
        let gauge = self
            .in_flight
            .get_or_create_owned(&ControlKindLabels { kind });
        gauge.inc();
        ControlRequestGuard { gauge }
    }

    fn complete(&self, kind: ControlRequestKind, outcome: ControlOutcome, elapsed: Duration) {
        self.requests
            .get_or_create(&ControlRequestLabels { kind, outcome })
            .inc();
        self.duration
            .get_or_create(&ControlKindLabels { kind })
            .observe(elapsed.as_secs_f64());
    }
}

struct ControlRequestGuard {
    gauge: Gauge,
}

impl Drop for ControlRequestGuard {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

struct ObservedRunnerControlClient {
    inner: Arc<dyn RunnerControlClient>,
    metrics: ControlMetrics,
}

struct ControlTransportObserver {
    metrics: ControlMetrics,
}

impl fmt::Debug for ControlTransportObserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlTransportObserver")
            .finish_non_exhaustive()
    }
}

impl RunnerControlClientObserver for ControlTransportObserver {
    fn observe_bytes(&self, direction: RunnerControlClientByteDirection, bytes: u64) {
        let direction = match direction {
            RunnerControlClientByteDirection::Request => ControlDirection::Sent,
            RunnerControlClientByteDirection::Response => ControlDirection::Received,
        };
        self.metrics
            .bytes
            .get_or_create(&ControlDirectionLabels { direction })
            .inc_by(bytes);
    }
}

impl fmt::Debug for ObservedRunnerControlClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedRunnerControlClient")
            .field("inner", &"configured")
            .finish_non_exhaustive()
    }
}

impl RunnerControlClient for ObservedRunnerControlClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> ClientFuture<'a> {
        Box::pin(async move {
            let kind = ControlRequestKind::from_request(request);
            let _in_flight = self.metrics.begin(kind);
            let started = Instant::now();
            let result = self.inner.exchange(request, cancellation).await;
            let outcome = result.as_ref().map_or_else(
                |error| ControlOutcome::from_error(error.kind()),
                |_| ControlOutcome::Success,
            );
            self.metrics.complete(kind, outcome, started.elapsed());
            if let Err(error) = result.as_ref()
                && error.retry_class() == RetryClass::Never
            {
                tracing::error!(
                    request_kind = ?kind,
                    error_kind = ?error.kind(),
                    retry = ?error.retry_class(),
                    "runner control request failed terminally"
                );
            }
            if result.is_ok() {
                self.metrics
                    .last_success_seconds
                    .set(unix_timestamp_seconds());
            }
            result
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RetryBackoffLabels {
    exchange: &'static str,
    cause: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RemoteErrorLabels {
    kind: &'static str,
    disposition: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct SessionLabels {
    mode: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct SessionModeLabels {
    mode: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ReasonLabels {
    reason: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct OutcomeLabels {
    outcome: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct DispositionLabels {
    disposition: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct CommandLabels {
    kind: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ModeLabels {
    mode: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ConclusionLabels {
    conclusion: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct KindLabels {
    kind: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct TerminalResultLabels {
    stage: &'static str,
    conclusion: &'static str,
}

type SessionDurationFamily = Family<SessionModeLabels, Histogram, fn() -> Histogram>;
type ConclusionDurationFamily = Family<ConclusionLabels, Histogram, fn() -> Histogram>;

fn semantic_duration_histogram() -> Histogram {
    classic_and_native_histogram([0.001, 0.005, 0.025, 0.1, 0.5, 1.0, 2.5, 10.0, 30.0])
}

fn job_duration_histogram() -> Histogram {
    classic_and_native_histogram([
        0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0, 900.0, 3_600.0, 21_600.0,
    ])
}

#[derive(Clone)]
struct SemanticMetrics {
    session_connected: Gauge,
    server_clock_offset_seconds: FloatGauge,
    retry_backoffs: Family<RetryBackoffLabels, Counter>,
    retry_backoff_duration: Histogram,
    remote_errors: Family<RemoteErrorLabels, Counter>,
    handshakes: Family<SessionLabels, Counter>,
    handshake_duration: SessionDurationFamily,
    reconnects: Family<ReasonLabels, Counter>,
    orphan_recoveries: Family<OutcomeLabels, Counter>,
    orphan_recovery_duration: Histogram,
    lease_polls: Family<OutcomeLabels, Counter>,
    lease_poll_duration: Histogram,
    lease_responses: Family<DispositionLabels, Counter>,
    heartbeat_renewals: Counter,
    heartbeat_renewal_duration: Histogram,
    lease_expirations: Counter,
    commands: Family<CommandLabels, Counter>,
    command_gap_waits: Counter,
    command_acknowledgements: Counter,
    jobs_started: Family<ModeLabels, Counter>,
    jobs_completed: Family<ConclusionLabels, Counter>,
    job_duration: ConclusionDurationFamily,
    infrastructure_failures: Family<KindLabels, Counter>,
    cancellations: Family<ReasonLabels, Counter>,
    log_batches_acknowledged: Counter,
    log_frames_acknowledged: Counter,
    log_acknowledged_bytes: Counter,
    log_acknowledgement_duration: Histogram,
    terminal_results: Family<TerminalResultLabels, Counter>,
    cleanups: Family<OutcomeLabels, Counter>,
    cleanup_duration: Histogram,
}

impl SemanticMetrics {
    #[allow(clippy::too_many_lines)]
    fn register(registry: &mut Registry) -> Self {
        let session_connected = register_gauge(
            registry,
            "runner_session_connected",
            "Whether this process currently has a live negotiated runner-control session",
        );
        let server_clock_offset_seconds = FloatGauge::default();
        registry.register_with_unit(
            "runner_control_server_clock_offset",
            "Signed server-minus-local wall-clock offset from the latest established session",
            Unit::Seconds,
            server_clock_offset_seconds.clone(),
        );

        let retry_backoffs = Family::<RetryBackoffLabels, Counter>::default();
        registry.register(
            "runner_control_retry_backoffs",
            "Exact-request retry backoffs scheduled by finite exchange kind and sanitized cause",
            retry_backoffs.clone(),
        );
        let retry_backoff_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_control_retry_backoff_duration",
            "Requested exact-request retry backoff duration across all exchange kinds",
            Unit::Seconds,
            retry_backoff_duration.clone(),
        );
        let remote_errors = Family::<RemoteErrorLabels, Counter>::default();
        registry.register(
            "runner_control_remote_errors",
            "Typed control-plane error responses by bounded category and runtime disposition",
            remote_errors.clone(),
        );

        let handshakes = Family::<SessionLabels, Counter>::default();
        registry.register(
            "runner_session_handshakes",
            "High-level runner session handshakes by request mode and semantic outcome",
            handshakes.clone(),
        );
        let handshake_duration = Family::<SessionModeLabels, Histogram, _>::new_with_constructor(
            semantic_duration_histogram as fn() -> Histogram,
        );
        registry.register_with_unit(
            "runner_session_handshake_duration",
            "High-level handshake duration including exact-request retries",
            Unit::Seconds,
            handshake_duration.clone(),
        );
        let reconnects = Family::<ReasonLabels, Counter>::default();
        registry.register(
            "runner_session_reconnects",
            "Runner session reconnects by closed reason",
            reconnects.clone(),
        );

        let orphan_recoveries = Family::<OutcomeLabels, Counter>::default();
        registry.register(
            "runner_orphan_recoveries",
            "Authorized orphan-recovery passes by closed outcome",
            orphan_recoveries.clone(),
        );
        let orphan_recovery_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_orphan_recovery_duration",
            "Authorized orphan-recovery pass duration across all outcomes",
            Unit::Seconds,
            orphan_recovery_duration.clone(),
        );

        let lease_polls = Family::<OutcomeLabels, Counter>::default();
        registry.register(
            "runner_lease_polls",
            "Stable-slot lease polls reaching a durable semantic outcome",
            lease_polls.clone(),
        );
        let lease_poll_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_lease_poll_duration",
            "Lease-poll duration excluding the no-work idle delay",
            Unit::Seconds,
            lease_poll_duration.clone(),
        );
        let lease_responses = Family::<DispositionLabels, Counter>::default();
        registry.register(
            "runner_lease_responses_acknowledged",
            "Lease dispositions acknowledged and advanced in durable runner state",
            lease_responses.clone(),
        );
        let heartbeat_renewals = Counter::default();
        registry.register(
            "runner_heartbeat_renewals",
            "Validated heartbeat renewals committed to the runner journal",
            heartbeat_renewals.clone(),
        );
        let heartbeat_renewal_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_heartbeat_renewal_duration",
            "Heartbeat renewal duration including semantic remote retries",
            Unit::Seconds,
            heartbeat_renewal_duration.clone(),
        );
        let lease_expirations = Counter::default();
        registry.register(
            "runner_lease_expirations",
            "Leases expired by the process-local monotonic watchdog",
            lease_expirations.clone(),
        );

        let commands = Family::<CommandLabels, Counter>::default();
        registry.register(
            "runner_commands",
            "Durable server commands by finite kind and applied, replayed, or ignored outcome",
            commands.clone(),
        );
        let command_gap_waits = Counter::default();
        registry.register(
            "runner_command_gap_waits",
            "Command handlers that waited for a missing durable predecessor",
            command_gap_waits.clone(),
        );
        let command_acknowledgements = Counter::default();
        registry.register(
            "runner_command_acknowledgements",
            "Cumulative durable command cursors acknowledged by the control plane",
            command_acknowledgements.clone(),
        );

        let jobs_started = Family::<ModeLabels, Counter>::default();
        registry.register(
            "runner_jobs_started",
            "Executor invocations started fresh or from recoverable durable state",
            jobs_started.clone(),
        );
        let jobs_completed = Family::<ConclusionLabels, Counter>::default();
        registry.register(
            "runner_jobs_completed",
            "New job completions committed by this process by finite conclusion",
            jobs_completed.clone(),
        );
        let job_duration = Family::<ConclusionLabels, Histogram, _>::new_with_constructor(
            job_duration_histogram as fn() -> Histogram,
        );
        registry.register_with_unit(
            "runner_job_duration",
            "Process-observed executor duration for newly committed job completions",
            Unit::Seconds,
            job_duration.clone(),
        );
        let infrastructure_failures = Family::<KindLabels, Counter>::default();
        registry.register(
            "runner_job_infrastructure_failures",
            "Sanitized executor and runtime-authority infrastructure failures",
            infrastructure_failures.clone(),
        );
        let cancellations = Family::<ReasonLabels, Counter>::default();
        registry.register(
            "runner_job_cancellations",
            "Executor cancellation signals by finite process-local reason",
            cancellations.clone(),
        );

        let log_batches_acknowledged = Counter::default();
        registry.register(
            "runner_log_batches_acknowledged",
            "Log batches durably compacted after control-plane acknowledgement",
            log_batches_acknowledged.clone(),
        );
        let log_frames_acknowledged = Counter::default();
        registry.register(
            "runner_log_frames_acknowledged",
            "Log frames durably compacted after control-plane acknowledgement",
            log_frames_acknowledged.clone(),
        );
        let log_acknowledged_bytes = Counter::default();
        registry.register_with_unit(
            "runner_log_acknowledged",
            "Logical log payload bytes durably compacted after acknowledgement",
            Unit::Bytes,
            log_acknowledged_bytes.clone(),
        );
        let log_acknowledgement_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_log_batch_acknowledgement_duration",
            "Log-batch delivery and durable acknowledgement-compaction duration",
            Unit::Seconds,
            log_acknowledgement_duration.clone(),
        );

        let terminal_results = Family::<TerminalResultLabels, Counter>::default();
        registry.register(
            "runner_terminal_results",
            "Durable terminal results by local commit or control-plane acknowledgement stage",
            terminal_results.clone(),
        );
        let cleanups = Family::<OutcomeLabels, Counter>::default();
        registry.register(
            "runner_cleanups",
            "Active-session terminal sandbox cleanup invocations by outcome",
            cleanups.clone(),
        );
        let cleanup_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_cleanup_duration",
            "Active-session terminal sandbox cleanup duration across all outcomes",
            Unit::Seconds,
            cleanup_duration.clone(),
        );

        let metrics = Self {
            session_connected,
            server_clock_offset_seconds,
            retry_backoffs,
            retry_backoff_duration,
            remote_errors,
            handshakes,
            handshake_duration,
            reconnects,
            orphan_recoveries,
            orphan_recovery_duration,
            lease_polls,
            lease_poll_duration,
            lease_responses,
            heartbeat_renewals,
            heartbeat_renewal_duration,
            lease_expirations,
            commands,
            command_gap_waits,
            command_acknowledgements,
            jobs_started,
            jobs_completed,
            job_duration,
            infrastructure_failures,
            cancellations,
            log_batches_acknowledged,
            log_frames_acknowledged,
            log_acknowledged_bytes,
            log_acknowledgement_duration,
            terminal_results,
            cleanups,
            cleanup_duration,
        };
        metrics.preinitialize();
        metrics
    }

    #[allow(clippy::too_many_lines)]
    fn preinitialize(&self) {
        const EXCHANGES: [&str; 10] = [
            "handshake",
            "lease_poll",
            "lease_response",
            "runtime_authority_request",
            "runtime_authority_ack",
            "heartbeat",
            "job_state",
            "job_result",
            "log_batch",
            "command_ack",
        ];
        const RETRY_CAUSES: [&str; 4] = [
            "unavailable",
            "timed_out",
            "invalid_response",
            "remote_response",
        ];
        const REMOTE_ERROR_KINDS: [&str; 9] = [
            "invalid_request",
            "compatibility",
            "authentication",
            "session",
            "operation_conflict",
            "lease_not_found",
            "stale_fencing_token",
            "retry_later",
            "internal",
        ];
        const SESSION_MODES: [&str; 2] = ["fresh", "resume"];
        const SESSION_OUTCOMES: [&str; 5] = [
            "opened",
            "resumed",
            "rejected",
            "exchange_error",
            "unexpected_response",
        ];
        const OPERATION_OUTCOMES: [&str; 3] = ["success", "error", "cancelled"];
        const POLL_OUTCOMES: [&str; 3] = ["no_work", "lease_offer", "cancellation"];
        const COMMAND_KINDS: [&str; 2] = ["lease_offer", "cancellation"];
        const COMMAND_OUTCOMES: [&str; 5] = [
            "applied",
            "replayed",
            "ignored_invalid",
            "ignored_slot_unavailable",
            "ignored_stale_lease",
        ];
        const CONCLUSIONS: [&str; 5] = ["success", "failure", "cancelled", "timed_out", "skipped"];
        const INFRASTRUCTURE_FAILURES: [&str; 11] = [
            "invalid_job",
            "unsupported",
            "resource_exhausted",
            "permission_denied",
            "unavailable",
            "timed_out",
            "cancelled",
            "internal",
            "task_terminated",
            "cancellation_timeout",
            "authority_expired",
        ];
        const CANCELLATION_REASONS: [&str; 6] = [
            "server_request",
            "lease_expired",
            "authority_expired",
            "session_lost",
            "control_failure",
            "shutdown",
        ];

        for exchange in EXCHANGES {
            for cause in RETRY_CAUSES {
                self.retry_backoffs
                    .get_or_create(&RetryBackoffLabels { exchange, cause })
                    .inc_by(0);
            }
        }
        for kind in REMOTE_ERROR_KINDS {
            for disposition in ["retrying", "terminal"] {
                if kind == "session" && disposition == "retrying" {
                    continue;
                }
                self.remote_errors
                    .get_or_create(&RemoteErrorLabels { kind, disposition })
                    .inc_by(0);
            }
        }
        for mode in SESSION_MODES {
            let _ = self
                .handshake_duration
                .get_or_create(&SessionModeLabels { mode });
            for outcome in SESSION_OUTCOMES {
                if mode == "fresh" && outcome == "resumed" {
                    continue;
                }
                self.handshakes
                    .get_or_create(&SessionLabels { mode, outcome })
                    .inc_by(0);
            }
        }
        self.reconnects
            .get_or_create(&ReasonLabels {
                reason: "stale_session",
            })
            .inc_by(0);
        for outcome in OPERATION_OUTCOMES {
            let labels = OutcomeLabels { outcome };
            self.orphan_recoveries.get_or_create(&labels).inc_by(0);
            self.cleanups.get_or_create(&labels).inc_by(0);
        }
        for outcome in POLL_OUTCOMES {
            let labels = OutcomeLabels { outcome };
            self.lease_polls.get_or_create(&labels).inc_by(0);
        }
        for disposition in ["accepted", "rejected"] {
            self.lease_responses
                .get_or_create(&DispositionLabels { disposition })
                .inc_by(0);
        }
        for kind in COMMAND_KINDS {
            for outcome in COMMAND_OUTCOMES {
                if matches!(
                    (kind, outcome),
                    ("lease_offer", "ignored_stale_lease")
                        | (
                            "cancellation",
                            "ignored_invalid" | "ignored_slot_unavailable"
                        )
                ) {
                    continue;
                }
                self.commands
                    .get_or_create(&CommandLabels { kind, outcome })
                    .inc_by(0);
            }
        }
        for mode in ["fresh", "recovered"] {
            self.jobs_started
                .get_or_create(&ModeLabels { mode })
                .inc_by(0);
        }
        for conclusion in CONCLUSIONS {
            let labels = ConclusionLabels { conclusion };
            self.jobs_completed.get_or_create(&labels).inc_by(0);
            let _ = self.job_duration.get_or_create(&labels);
            for stage in ["committed", "acknowledged"] {
                self.terminal_results
                    .get_or_create(&TerminalResultLabels { stage, conclusion })
                    .inc_by(0);
            }
        }
        for kind in INFRASTRUCTURE_FAILURES {
            self.infrastructure_failures
                .get_or_create(&KindLabels { kind })
                .inc_by(0);
        }
        for reason in CANCELLATION_REASONS {
            self.cancellations
                .get_or_create(&ReasonLabels { reason })
                .inc_by(0);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn observe(&self, event: RunnerRuntimeEvent) {
        match event {
            RunnerRuntimeEvent::RetryBackoff {
                exchange,
                cause,
                delay,
            } => {
                let exchange = exchange_label(exchange);
                self.retry_backoffs
                    .get_or_create(&RetryBackoffLabels {
                        exchange,
                        cause: retry_cause_label(cause),
                    })
                    .inc();
                self.retry_backoff_duration.observe(delay.as_secs_f64());
            }
            RunnerRuntimeEvent::RetryAttempt { .. } => {}
            RunnerRuntimeEvent::SessionHandshake {
                mode,
                outcome,
                duration,
            } => {
                let mode = session_mode_label(mode);
                self.handshakes
                    .get_or_create(&SessionLabels {
                        mode,
                        outcome: session_outcome_label(outcome),
                    })
                    .inc();
                self.handshake_duration
                    .get_or_create(&SessionModeLabels { mode })
                    .observe(duration.as_secs_f64());
            }
            RunnerRuntimeEvent::SessionConnected {
                server_clock_offset_millis,
            } => {
                self.session_connected.set(1);
                self.server_clock_offset_seconds
                    .set(milliseconds_as_seconds(server_clock_offset_millis));
            }
            RunnerRuntimeEvent::SessionDisconnected => {
                self.session_connected.set(0);
            }
            RunnerRuntimeEvent::Reconnect { reason } => {
                self.reconnects
                    .get_or_create(&ReasonLabels {
                        reason: reconnect_reason_label(reason),
                    })
                    .inc();
            }
            RunnerRuntimeEvent::RemoteError {
                exchange: _,
                kind,
                disposition,
            } => {
                self.remote_errors
                    .get_or_create(&RemoteErrorLabels {
                        kind: remote_error_kind_label(kind),
                        disposition: remote_error_disposition_label(disposition),
                    })
                    .inc();
            }
            RunnerRuntimeEvent::OrphanRecovery { outcome, duration } => {
                let labels = OutcomeLabels {
                    outcome: operation_outcome_label(outcome),
                };
                self.orphan_recoveries.get_or_create(&labels).inc();
                self.orphan_recovery_duration
                    .observe(duration.as_secs_f64());
            }
            RunnerRuntimeEvent::LeasePoll { outcome, duration } => {
                let labels = OutcomeLabels {
                    outcome: lease_poll_outcome_label(outcome),
                };
                self.lease_polls.get_or_create(&labels).inc();
                self.lease_poll_duration.observe(duration.as_secs_f64());
            }
            RunnerRuntimeEvent::LeaseResponseAcknowledged { disposition } => {
                self.lease_responses
                    .get_or_create(&DispositionLabels {
                        disposition: lease_disposition_label(disposition),
                    })
                    .inc();
            }
            RunnerRuntimeEvent::LeaseRenewed { duration } => {
                self.heartbeat_renewals.inc();
                self.heartbeat_renewal_duration
                    .observe(duration.as_secs_f64());
            }
            RunnerRuntimeEvent::LeaseExpired => {
                self.lease_expirations.inc();
            }
            RunnerRuntimeEvent::Command { kind, outcome } => {
                self.commands
                    .get_or_create(&CommandLabels {
                        kind: command_kind_label(kind),
                        outcome: command_outcome_label(outcome),
                    })
                    .inc();
            }
            RunnerRuntimeEvent::CommandGapWait => {
                self.command_gap_waits.inc();
            }
            RunnerRuntimeEvent::CommandAcknowledged => {
                self.command_acknowledgements.inc();
            }
            RunnerRuntimeEvent::JobStarted { mode } => {
                self.jobs_started
                    .get_or_create(&ModeLabels {
                        mode: job_start_mode_label(mode),
                    })
                    .inc();
            }
            RunnerRuntimeEvent::JobCompleted {
                conclusion,
                duration,
            } => {
                let labels = ConclusionLabels {
                    conclusion: job_conclusion_label(conclusion),
                };
                self.jobs_completed.get_or_create(&labels).inc();
                if let Some(duration) = duration {
                    self.job_duration
                        .get_or_create(&labels)
                        .observe(duration.as_secs_f64());
                }
            }
            RunnerRuntimeEvent::InfrastructureFailure { kind } => {
                self.infrastructure_failures
                    .get_or_create(&KindLabels {
                        kind: infrastructure_failure_label(kind),
                    })
                    .inc();
            }
            RunnerRuntimeEvent::Cancellation { reason } => {
                self.cancellations
                    .get_or_create(&ReasonLabels {
                        reason: cancellation_reason_label(reason),
                    })
                    .inc();
            }
            RunnerRuntimeEvent::LogBatchAcknowledged {
                frames,
                bytes,
                duration,
            } => {
                self.log_batches_acknowledged.inc();
                self.log_frames_acknowledged.inc_by(frames);
                self.log_acknowledged_bytes.inc_by(bytes);
                self.log_acknowledgement_duration
                    .observe(duration.as_secs_f64());
            }
            RunnerRuntimeEvent::TerminalResult { stage, conclusion } => {
                self.terminal_results
                    .get_or_create(&TerminalResultLabels {
                        stage: terminal_stage_label(stage),
                        conclusion: job_conclusion_label(conclusion),
                    })
                    .inc();
            }
            RunnerRuntimeEvent::Cleanup { outcome, duration } => {
                let labels = OutcomeLabels {
                    outcome: operation_outcome_label(outcome),
                };
                self.cleanups.get_or_create(&labels).inc();
                self.cleanup_duration.observe(duration.as_secs_f64());
            }
        }
    }
}

impl RunnerRuntimeObserver for RunnerMetrics {
    fn observe(&self, event: RunnerRuntimeEvent) {
        if let RunnerRuntimeEvent::RetryAttempt { exchange } = event {
            self.control
                .retries
                .get_or_create(&ControlKindLabels {
                    kind: control_kind_from_exchange(exchange),
                })
                .inc();
        } else {
            self.semantic.observe(event);
        }
    }
}

const fn exchange_label(value: RuntimeExchangeKind) -> &'static str {
    match value {
        RuntimeExchangeKind::Handshake => "handshake",
        RuntimeExchangeKind::LeasePoll => "lease_poll",
        RuntimeExchangeKind::LeaseResponse => "lease_response",
        RuntimeExchangeKind::RuntimeAuthorityRequest => "runtime_authority_request",
        RuntimeExchangeKind::RuntimeAuthorityAck => "runtime_authority_ack",
        RuntimeExchangeKind::Heartbeat => "heartbeat",
        RuntimeExchangeKind::JobState => "job_state",
        RuntimeExchangeKind::JobResult => "job_result",
        RuntimeExchangeKind::LogBatch => "log_batch",
        RuntimeExchangeKind::CommandAck => "command_ack",
    }
}

const fn control_kind_from_exchange(value: RuntimeExchangeKind) -> ControlRequestKind {
    match value {
        RuntimeExchangeKind::Handshake => ControlRequestKind::Handshake,
        RuntimeExchangeKind::LeasePoll => ControlRequestKind::LeaseRequest,
        RuntimeExchangeKind::LeaseResponse => ControlRequestKind::LeaseResponse,
        RuntimeExchangeKind::RuntimeAuthorityRequest => ControlRequestKind::RuntimeAuthorityRequest,
        RuntimeExchangeKind::RuntimeAuthorityAck => ControlRequestKind::RuntimeAuthorityAck,
        RuntimeExchangeKind::Heartbeat => ControlRequestKind::Heartbeat,
        RuntimeExchangeKind::JobState => ControlRequestKind::JobState,
        RuntimeExchangeKind::JobResult => ControlRequestKind::JobResult,
        RuntimeExchangeKind::LogBatch => ControlRequestKind::LogBatch,
        RuntimeExchangeKind::CommandAck => ControlRequestKind::CommandAck,
    }
}

const fn retry_cause_label(value: RuntimeRetryCause) -> &'static str {
    match value {
        RuntimeRetryCause::Unavailable => "unavailable",
        RuntimeRetryCause::TimedOut => "timed_out",
        RuntimeRetryCause::InvalidResponse => "invalid_response",
        RuntimeRetryCause::RemoteResponse => "remote_response",
    }
}

const fn remote_error_kind_label(value: RuntimeRemoteErrorKind) -> &'static str {
    match value {
        RuntimeRemoteErrorKind::InvalidRequest => "invalid_request",
        RuntimeRemoteErrorKind::Compatibility => "compatibility",
        RuntimeRemoteErrorKind::Authentication => "authentication",
        RuntimeRemoteErrorKind::Session => "session",
        RuntimeRemoteErrorKind::OperationConflict => "operation_conflict",
        RuntimeRemoteErrorKind::LeaseNotFound => "lease_not_found",
        RuntimeRemoteErrorKind::StaleFencingToken => "stale_fencing_token",
        RuntimeRemoteErrorKind::RetryLater => "retry_later",
        RuntimeRemoteErrorKind::Internal => "internal",
    }
}

const fn remote_error_disposition_label(value: RuntimeRemoteErrorDisposition) -> &'static str {
    match value {
        RuntimeRemoteErrorDisposition::Retrying => "retrying",
        RuntimeRemoteErrorDisposition::Terminal => "terminal",
    }
}

const fn session_mode_label(value: RuntimeSessionMode) -> &'static str {
    match value {
        RuntimeSessionMode::Fresh => "fresh",
        RuntimeSessionMode::Resume => "resume",
    }
}

const fn session_outcome_label(value: RuntimeSessionOutcome) -> &'static str {
    match value {
        RuntimeSessionOutcome::Opened => "opened",
        RuntimeSessionOutcome::Resumed => "resumed",
        RuntimeSessionOutcome::Rejected => "rejected",
        RuntimeSessionOutcome::ExchangeError => "exchange_error",
        RuntimeSessionOutcome::UnexpectedResponse => "unexpected_response",
    }
}

const fn reconnect_reason_label(value: RuntimeReconnectReason) -> &'static str {
    match value {
        RuntimeReconnectReason::StaleSession => "stale_session",
    }
}

const fn operation_outcome_label(value: RuntimeOperationOutcome) -> &'static str {
    match value {
        RuntimeOperationOutcome::Success => "success",
        RuntimeOperationOutcome::Error => "error",
        RuntimeOperationOutcome::Cancelled => "cancelled",
    }
}

const fn lease_poll_outcome_label(value: RuntimeLeasePollOutcome) -> &'static str {
    match value {
        RuntimeLeasePollOutcome::NoWork => "no_work",
        RuntimeLeasePollOutcome::LeaseOffer => "lease_offer",
        RuntimeLeasePollOutcome::Cancellation => "cancellation",
    }
}

const fn lease_disposition_label(value: RuntimeLeaseDisposition) -> &'static str {
    match value {
        RuntimeLeaseDisposition::Accepted => "accepted",
        RuntimeLeaseDisposition::Rejected => "rejected",
    }
}

const fn command_kind_label(value: RuntimeCommandKind) -> &'static str {
    match value {
        RuntimeCommandKind::LeaseOffer => "lease_offer",
        RuntimeCommandKind::Cancellation => "cancellation",
    }
}

const fn command_outcome_label(value: RuntimeCommandOutcome) -> &'static str {
    match value {
        RuntimeCommandOutcome::Applied => "applied",
        RuntimeCommandOutcome::Replayed => "replayed",
        RuntimeCommandOutcome::IgnoredInvalid => "ignored_invalid",
        RuntimeCommandOutcome::IgnoredSlotUnavailable => "ignored_slot_unavailable",
        RuntimeCommandOutcome::IgnoredStaleLease => "ignored_stale_lease",
    }
}

const fn job_start_mode_label(value: RuntimeJobStartMode) -> &'static str {
    match value {
        RuntimeJobStartMode::Fresh => "fresh",
        RuntimeJobStartMode::Recovered => "recovered",
    }
}

const fn job_conclusion_label(value: RuntimeJobConclusion) -> &'static str {
    match value {
        RuntimeJobConclusion::Success => "success",
        RuntimeJobConclusion::Failure => "failure",
        RuntimeJobConclusion::Cancelled => "cancelled",
        RuntimeJobConclusion::TimedOut => "timed_out",
        RuntimeJobConclusion::Skipped => "skipped",
    }
}

const fn infrastructure_failure_label(value: RuntimeInfrastructureFailure) -> &'static str {
    match value {
        RuntimeInfrastructureFailure::InvalidJob => "invalid_job",
        RuntimeInfrastructureFailure::Unsupported => "unsupported",
        RuntimeInfrastructureFailure::ResourceExhausted => "resource_exhausted",
        RuntimeInfrastructureFailure::PermissionDenied => "permission_denied",
        RuntimeInfrastructureFailure::Unavailable => "unavailable",
        RuntimeInfrastructureFailure::TimedOut => "timed_out",
        RuntimeInfrastructureFailure::Cancelled => "cancelled",
        RuntimeInfrastructureFailure::Internal => "internal",
        RuntimeInfrastructureFailure::TaskTerminated => "task_terminated",
        RuntimeInfrastructureFailure::CancellationTimeout => "cancellation_timeout",
        RuntimeInfrastructureFailure::AuthorityExpired => "authority_expired",
    }
}

const fn cancellation_reason_label(value: RuntimeCancellationReason) -> &'static str {
    match value {
        RuntimeCancellationReason::ServerRequest => "server_request",
        RuntimeCancellationReason::LeaseExpired => "lease_expired",
        RuntimeCancellationReason::AuthorityExpired => "authority_expired",
        RuntimeCancellationReason::SessionLost => "session_lost",
        RuntimeCancellationReason::ControlFailure => "control_failure",
        RuntimeCancellationReason::Shutdown => "shutdown",
    }
}

const fn terminal_stage_label(value: RuntimeTerminalResultStage) -> &'static str {
    match value {
        RuntimeTerminalResultStage::Committed => "committed",
        RuntimeTerminalResultStage::Acknowledged => "acknowledged",
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct OperationOutcomeLabels {
    operation: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct OperationLabels {
    operation: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct OperationKindLabels {
    operation: &'static str,
    kind: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ProtectionLabels {
    operation: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ResourceLabels {
    resource: &'static str,
}

#[derive(Clone)]
struct SpoolMetrics {
    operations: Family<OperationOutcomeLabels, Counter>,
    duration: Histogram,
    in_flight: Family<OperationLabels, Gauge>,
    failures: Family<KindLabels, Counter>,
    content_operations: Family<OperationKindLabels, Counter>,
    content_bytes: Family<OperationKindLabels, Counter>,
    protection: Family<ProtectionLabels, Counter>,
    capacity_rejections: Family<ResourceLabels, Counter>,
    reclaimed_objects: Counter,
    reclaimed_bytes: Counter,
    poison_events: Family<OperationLabels, Counter>,
}

impl SpoolMetrics {
    fn register(registry: &mut Registry) -> Self {
        let operations = Family::<OperationOutcomeLabels, Counter>::default();
        registry.register(
            "runner_spool_operations",
            "Protected-spool operations by finite operation and terminal outcome",
            operations.clone(),
        );
        let duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_spool_operation_duration",
            "Protected-spool operation duration across all operation kinds",
            Unit::Seconds,
            duration.clone(),
        );
        let in_flight = Family::<OperationLabels, Gauge>::default();
        registry.register(
            "runner_spool_operations_in_flight",
            "Protected-spool operations currently in flight by finite operation",
            in_flight.clone(),
        );
        let failures = Family::<KindLabels, Counter>::default();
        registry.register(
            "runner_spool_failures",
            "Protected-spool failures by bounded secret-free category",
            failures.clone(),
        );
        let content_operations = Family::<OperationKindLabels, Counter>::default();
        registry.register(
            "runner_spool_content_operations",
            "Protected content operations by finite operation and semantic content kind",
            content_operations.clone(),
        );
        let content_bytes = Family::<OperationKindLabels, Counter>::default();
        registry.register_with_unit(
            "runner_spool_content",
            "Logical protected-content bytes completed by operation and semantic kind",
            Unit::Bytes,
            content_bytes.clone(),
        );
        let protection = Family::<ProtectionLabels, Counter>::default();
        registry.register(
            "runner_spool_protection_operations",
            "Content protection operations by direction and sanitized outcome",
            protection.clone(),
        );
        let capacity_rejections = Family::<ResourceLabels, Counter>::default();
        registry.register(
            "runner_spool_capacity_rejections",
            "Protected-spool operations rejected by configured resource bound",
            capacity_rejections.clone(),
        );
        let reclaimed_objects = Counter::default();
        registry.register(
            "runner_spool_reclaimed_objects",
            "Payload-first crash leftovers removed by successful reconciliation",
            reclaimed_objects.clone(),
        );
        let reclaimed_bytes = Counter::default();
        registry.register_with_unit(
            "runner_spool_reclaimed",
            "Protected bytes removed by successful reconciliation",
            Unit::Bytes,
            reclaimed_bytes.clone(),
        );
        let poison_events = Family::<OperationLabels, Counter>::default();
        registry.register(
            "runner_spool_poison_events",
            "Uncertain durable outcomes that poisoned the open spool handle",
            poison_events.clone(),
        );

        let metrics = Self {
            operations,
            duration,
            in_flight,
            failures,
            content_operations,
            content_bytes,
            protection,
            capacity_rejections,
            reclaimed_objects,
            reclaimed_bytes,
            poison_events,
        };
        metrics.preinitialize();
        metrics
    }

    fn preinitialize(&self) {
        for operation in ["persist", "load", "remove", "reconcile"] {
            self.in_flight
                .get_or_create(&OperationLabels { operation })
                .set(0);
            for outcome in ["success", "already_absent", "error"] {
                if outcome == "already_absent" && operation != "remove" {
                    continue;
                }
                self.operations
                    .get_or_create(&OperationOutcomeLabels { operation, outcome })
                    .inc_by(0);
            }
        }
        for kind in [
            "invalid_input",
            "protection_key_unavailable",
            "authentication",
            "protection",
            "capacity",
            "fenced",
            "missing",
            "uncertain",
            "poisoned",
            "path_security",
            "io",
            "unsupported",
        ] {
            self.failures.get_or_create(&KindLabels { kind }).inc_by(0);
        }
        for operation in ["persist", "load", "remove"] {
            for kind in [
                "job_ir",
                "runtime_authority",
                "terminal_result",
                "log_spool",
            ] {
                let labels = OperationKindLabels { operation, kind };
                self.content_operations.get_or_create(&labels).inc_by(0);
                self.content_bytes.get_or_create(&labels).inc_by(0);
            }
        }
        for operation in ["protect", "unprotect"] {
            for outcome in ["success", "error"] {
                self.protection
                    .get_or_create(&ProtectionLabels { operation, outcome })
                    .inc_by(0);
            }
        }
        for resource in ["object_bytes", "object_count", "protected_bytes"] {
            self.capacity_rejections
                .get_or_create(&ResourceLabels { resource })
                .inc_by(0);
        }
        for operation in ["persist", "remove", "reconcile"] {
            self.poison_events
                .get_or_create(&OperationLabels { operation })
                .inc_by(0);
        }
    }

    fn observe(&self, event: SpoolEvent) {
        match event {
            SpoolEvent::OperationStarted { operation } => {
                self.in_flight
                    .get_or_create(&OperationLabels {
                        operation: spool_operation_label(operation),
                    })
                    .inc();
            }
            SpoolEvent::OperationCompleted {
                operation,
                content_kind,
                outcome,
                failure,
                duration,
            } => {
                let operation = spool_operation_label(operation);
                self.in_flight
                    .get_or_create(&OperationLabels { operation })
                    .dec();
                self.operations
                    .get_or_create(&OperationOutcomeLabels {
                        operation,
                        outcome: spool_outcome_label(outcome),
                    })
                    .inc();
                self.duration.observe(duration.as_secs_f64());
                if let Some(failure) = failure {
                    self.failures
                        .get_or_create(&KindLabels {
                            kind: spool_failure_label(failure),
                        })
                        .inc();
                }
                if let Some(content_kind) = content_kind {
                    self.content_operations
                        .get_or_create(&OperationKindLabels {
                            operation,
                            kind: content_kind_label(content_kind),
                        })
                        .inc();
                }
            }
            SpoolEvent::ContentBytes {
                operation,
                content_kind,
                bytes,
            } => {
                self.content_bytes
                    .get_or_create(&OperationKindLabels {
                        operation: spool_operation_label(operation),
                        kind: content_kind_label(content_kind),
                    })
                    .inc_by(bytes);
            }
            SpoolEvent::Protection { operation, outcome } => {
                self.protection
                    .get_or_create(&ProtectionLabels {
                        operation: protection_operation_label(operation),
                        outcome: protection_outcome_label(outcome),
                    })
                    .inc();
            }
            SpoolEvent::CapacityRejected { resource } => {
                self.capacity_rejections
                    .get_or_create(&ResourceLabels {
                        resource: capacity_resource_label(resource),
                    })
                    .inc();
            }
            SpoolEvent::Reclaimed {
                objects,
                protected_bytes,
            } => {
                self.reclaimed_objects.inc_by(objects);
                self.reclaimed_bytes.inc_by(protected_bytes);
            }
            SpoolEvent::Poisoned { operation } => {
                self.poison_events
                    .get_or_create(&OperationLabels {
                        operation: spool_operation_label(operation),
                    })
                    .inc();
            }
        }
    }
}

impl SpoolObserver for RunnerMetrics {
    fn observe(&self, event: SpoolEvent) {
        self.spool_operations.observe(event);
    }
}

const fn spool_operation_label(value: SpoolOperation) -> &'static str {
    match value {
        SpoolOperation::Persist => "persist",
        SpoolOperation::Load => "load",
        SpoolOperation::Remove => "remove",
        SpoolOperation::Reconcile => "reconcile",
    }
}

const fn spool_outcome_label(value: SpoolOperationOutcome) -> &'static str {
    match value {
        SpoolOperationOutcome::Success => "success",
        SpoolOperationOutcome::AlreadyAbsent => "already_absent",
        SpoolOperationOutcome::Error => "error",
    }
}

const fn content_kind_label(value: ContentKind) -> &'static str {
    match value {
        ContentKind::JobIr => "job_ir",
        ContentKind::RuntimeAuthority => "runtime_authority",
        ContentKind::TerminalResult => "terminal_result",
        ContentKind::LogSpool => "log_spool",
    }
}

const fn spool_failure_label(value: SpoolFailureKind) -> &'static str {
    match value {
        SpoolFailureKind::InvalidInput => "invalid_input",
        SpoolFailureKind::ProtectionKeyUnavailable => "protection_key_unavailable",
        SpoolFailureKind::Authentication => "authentication",
        SpoolFailureKind::Protection => "protection",
        SpoolFailureKind::Capacity => "capacity",
        SpoolFailureKind::Fenced => "fenced",
        SpoolFailureKind::Missing => "missing",
        SpoolFailureKind::Uncertain => "uncertain",
        SpoolFailureKind::Poisoned => "poisoned",
        SpoolFailureKind::PathSecurity => "path_security",
        SpoolFailureKind::Io => "io",
        SpoolFailureKind::Unsupported => "unsupported",
    }
}

const fn protection_operation_label(value: SpoolProtectionOperation) -> &'static str {
    match value {
        SpoolProtectionOperation::Protect => "protect",
        SpoolProtectionOperation::Unprotect => "unprotect",
    }
}

const fn protection_outcome_label(value: SpoolProtectionOutcome) -> &'static str {
    match value {
        SpoolProtectionOutcome::Success => "success",
        SpoolProtectionOutcome::Error => "error",
    }
}

const fn capacity_resource_label(value: SpoolCapacityResource) -> &'static str {
    match value {
        SpoolCapacityResource::ObjectBytes => "object_bytes",
        SpoolCapacityResource::ObjectCount => "object_count",
        SpoolCapacityResource::ProtectedBytes => "protected_bytes",
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SandboxProviderOperation {
    Create,
    Attach,
    Inspect,
    ServiceBindings,
    Destroy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SandboxEndpointOperation {
    Exec,
    Signal,
    Wait,
    CopyTo,
    CopyFrom,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct DirectionLabels {
    direction: &'static str,
}

#[derive(Clone)]
struct SandboxMetrics {
    provider_operations: Family<OperationOutcomeLabels, Counter>,
    provider_duration: Histogram,
    provider_in_flight: Family<OperationLabels, Gauge>,
    provider_errors: Family<KindLabels, Counter>,
    endpoint_operations: Family<OperationOutcomeLabels, Counter>,
    endpoint_duration: Histogram,
    endpoint_in_flight: Family<OperationLabels, Gauge>,
    endpoint_errors: Family<KindLabels, Counter>,
    endpoint_bytes: Family<DirectionLabels, Counter>,
    endpoint_terminations: Family<KindLabels, Counter>,
    endpoint_output_truncations: Counter,
}

impl SandboxMetrics {
    fn register(registry: &mut Registry) -> Self {
        let provider_operations = Family::<OperationOutcomeLabels, Counter>::default();
        registry.register(
            "runner_sandbox_provider_operations",
            "Provider-neutral sandbox operations by finite operation and outcome",
            provider_operations.clone(),
        );
        let provider_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_sandbox_provider_operation_duration",
            "Provider-neutral sandbox operation duration across all operations",
            Unit::Seconds,
            provider_duration.clone(),
        );
        let provider_in_flight = Family::<OperationLabels, Gauge>::default();
        registry.register(
            "runner_sandbox_provider_operations_in_flight",
            "Provider-neutral sandbox operations currently in flight",
            provider_in_flight.clone(),
        );
        let provider_errors = Family::<KindLabels, Counter>::default();
        registry.register(
            "runner_sandbox_provider_errors",
            "Provider-neutral sandbox errors by bounded typed category",
            provider_errors.clone(),
        );

        let endpoint_operations = Family::<OperationOutcomeLabels, Counter>::default();
        registry.register(
            "runner_sandbox_endpoint_operations",
            "Returned execution-endpoint operations by finite operation and outcome",
            endpoint_operations.clone(),
        );
        let endpoint_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_sandbox_endpoint_operation_duration",
            "Returned execution-endpoint operation duration across all operations",
            Unit::Seconds,
            endpoint_duration.clone(),
        );
        let endpoint_in_flight = Family::<OperationLabels, Gauge>::default();
        registry.register(
            "runner_sandbox_endpoint_operations_in_flight",
            "Returned execution-endpoint operations currently in flight",
            endpoint_in_flight.clone(),
        );
        let endpoint_errors = Family::<KindLabels, Counter>::default();
        registry.register(
            "runner_sandbox_endpoint_errors",
            "Returned execution-endpoint errors by bounded typed category",
            endpoint_errors.clone(),
        );
        let endpoint_bytes = Family::<DirectionLabels, Counter>::default();
        registry.register_with_unit(
            "runner_sandbox_endpoint",
            "Complete stdout, stderr, copy-in, and copy-out payload bytes",
            Unit::Bytes,
            endpoint_bytes.clone(),
        );
        let endpoint_terminations = Family::<KindLabels, Counter>::default();
        registry.register(
            "runner_sandbox_endpoint_terminations",
            "Successful exec call returns by bounded process termination",
            endpoint_terminations.clone(),
        );
        let endpoint_output_truncations = Counter::default();
        registry.register(
            "runner_sandbox_endpoint_output_truncations",
            "Successful exec outputs truncated at the configured capture bound",
            endpoint_output_truncations.clone(),
        );

        let metrics = Self {
            provider_operations,
            provider_duration,
            provider_in_flight,
            provider_errors,
            endpoint_operations,
            endpoint_duration,
            endpoint_in_flight,
            endpoint_errors,
            endpoint_bytes,
            endpoint_terminations,
            endpoint_output_truncations,
        };
        metrics.preinitialize();
        metrics
    }

    fn preinitialize(&self) {
        for operation in ["create", "attach", "inspect", "service_bindings", "destroy"] {
            self.provider_in_flight
                .get_or_create(&OperationLabels { operation })
                .set(0);
            for outcome in ["success", "error", "cancelled", "timed_out"] {
                self.provider_operations
                    .get_or_create(&OperationOutcomeLabels { operation, outcome })
                    .inc_by(0);
            }
        }
        for kind in [
            "unsupported_platform",
            "unsupported_capability",
            "cancelled",
            "timed_out",
            "adapter_unavailable",
            "invalid_configuration",
            "not_found",
            "conflict",
            "ownership_mismatch",
            "invalid_state",
            "output_limit_exceeded",
            "backend_rejected",
            "local_storage",
        ] {
            self.provider_errors
                .get_or_create(&KindLabels { kind })
                .inc_by(0);
        }

        for operation in ["exec", "signal", "wait", "copy_to", "copy_from"] {
            self.endpoint_in_flight
                .get_or_create(&OperationLabels { operation })
                .set(0);
            for outcome in ["success", "error", "cancelled", "timed_out"] {
                self.endpoint_operations
                    .get_or_create(&OperationOutcomeLabels { operation, outcome })
                    .inc_by(0);
            }
        }
        for kind in [
            "unsupported_capability",
            "invalid_environment",
            "cancelled",
            "timed_out",
            "not_found",
            "ownership_mismatch",
            "invalid_state",
            "output_limit_exceeded",
            "backend_rejected",
            "local_storage",
        ] {
            self.endpoint_errors
                .get_or_create(&KindLabels { kind })
                .inc_by(0);
        }
        for direction in ["stdout", "stderr", "copy_to", "copy_from"] {
            self.endpoint_bytes
                .get_or_create(&DirectionLabels { direction })
                .inc_by(0);
        }
        for kind in ["exited", "signalled", "timed_out", "cancelled"] {
            self.endpoint_terminations
                .get_or_create(&KindLabels { kind })
                .inc_by(0);
        }
    }

    fn begin_provider(&self, operation: SandboxProviderOperation) -> ControlRequestGuard {
        let gauge = self
            .provider_in_flight
            .get_or_create_owned(&OperationLabels {
                operation: provider_operation_label(operation),
            });
        gauge.inc();
        ControlRequestGuard { gauge }
    }

    fn complete_provider<T>(
        &self,
        operation: SandboxProviderOperation,
        started: Instant,
        result: &Result<T, ProviderError>,
    ) {
        let outcome = result
            .as_ref()
            .map_or_else(|error| provider_outcome_label(error.kind()), |_| "success");
        self.provider_operations
            .get_or_create(&OperationOutcomeLabels {
                operation: provider_operation_label(operation),
                outcome,
            })
            .inc();
        self.provider_duration
            .observe(started.elapsed().as_secs_f64());
        if let Err(error) = result {
            self.provider_errors
                .get_or_create(&KindLabels {
                    kind: provider_error_label(error.kind()),
                })
                .inc();
        }
    }

    fn begin_endpoint(&self, operation: SandboxEndpointOperation) -> ControlRequestGuard {
        let gauge = self
            .endpoint_in_flight
            .get_or_create_owned(&OperationLabels {
                operation: endpoint_operation_label(operation),
            });
        gauge.inc();
        ControlRequestGuard { gauge }
    }

    fn complete_endpoint<T>(
        &self,
        operation: SandboxEndpointOperation,
        started: Instant,
        result: &Result<T, ExecutionError>,
    ) {
        let outcome = result
            .as_ref()
            .map_or_else(|error| endpoint_outcome_label(error.kind()), |_| "success");
        self.endpoint_operations
            .get_or_create(&OperationOutcomeLabels {
                operation: endpoint_operation_label(operation),
                outcome,
            })
            .inc();
        self.endpoint_duration
            .observe(started.elapsed().as_secs_f64());
        if let Err(error) = result {
            self.endpoint_errors
                .get_or_create(&KindLabels {
                    kind: endpoint_error_label(error.kind()),
                })
                .inc();
        }
    }
}

struct ObservedSandboxProvider {
    inner: Arc<dyn SandboxProvider>,
    metrics: SandboxMetrics,
}

impl ObservedSandboxProvider {
    fn call<T>(
        &self,
        operation: SandboxProviderOperation,
        call: impl FnOnce() -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let _in_flight = self.metrics.begin_provider(operation);
        let started = Instant::now();
        let result = call();
        self.metrics.complete_provider(operation, started, &result);
        result
    }
}

impl fmt::Debug for ObservedSandboxProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedSandboxProvider")
            .field("inner", &"configured")
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for ObservedSandboxProvider {
    fn provider_id(&self) -> &ProviderId {
        self.inner.provider_id()
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        self.inner.capabilities()
    }

    fn create(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        self.call(SandboxProviderOperation::Create, || {
            self.inner.create(spec, cancellation)
        })
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        let endpoint = self.call(SandboxProviderOperation::Attach, || {
            self.inner.attach(handle, cancellation)
        })?;
        Ok(Box::new(ObservedExecutionEndpoint {
            inner: endpoint,
            metrics: self.metrics.clone(),
        }))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        self.call(SandboxProviderOperation::Inspect, || {
            self.inner.inspect(handle, cancellation)
        })
    }

    fn service_bindings(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<ServiceContainerBindings, ProviderError> {
        self.call(SandboxProviderOperation::ServiceBindings, || {
            self.inner.service_bindings(handle, cancellation)
        })
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        self.call(SandboxProviderOperation::Destroy, || {
            self.inner.destroy(request, cancellation)
        })
    }
}

struct ObservedExecutionEndpoint {
    inner: Box<dyn ExecutionEndpoint>,
    metrics: SandboxMetrics,
}

impl ObservedExecutionEndpoint {
    fn call<T>(
        &self,
        operation: SandboxEndpointOperation,
        call: impl FnOnce() -> Result<T, ExecutionError>,
    ) -> Result<T, ExecutionError> {
        let _in_flight = self.metrics.begin_endpoint(operation);
        let started = Instant::now();
        let result = call();
        self.metrics.complete_endpoint(operation, started, &result);
        result
    }
}

impl fmt::Debug for ObservedExecutionEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedExecutionEndpoint")
            .field("inner", &"configured")
            .finish_non_exhaustive()
    }
}

impl ExecutionEndpoint for ObservedExecutionEndpoint {
    fn handle(&self) -> &SandboxHandle {
        self.inner.handle()
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        self.inner.capabilities()
    }

    fn exec(
        &self,
        request: &ExecutionCommand,
        cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let result = self.call(SandboxEndpointOperation::Exec, || {
            self.inner.exec(request, cancellation)
        });
        if let Ok(output) = &result {
            self.metrics
                .endpoint_bytes
                .get_or_create(&DirectionLabels {
                    direction: "stdout",
                })
                .inc_by(saturating_u64(output.stdout().len()));
            self.metrics
                .endpoint_bytes
                .get_or_create(&DirectionLabels {
                    direction: "stderr",
                })
                .inc_by(saturating_u64(output.stderr().len()));
            self.metrics
                .endpoint_terminations
                .get_or_create(&KindLabels {
                    kind: execution_termination_label(output.termination()),
                })
                .inc();
            if output.was_truncated() {
                self.metrics.endpoint_output_truncations.inc();
            }
        }
        result
    }

    fn signal(
        &self,
        request: SignalRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        self.call(SandboxEndpointOperation::Signal, || {
            self.inner.signal(request, cancellation)
        })
    }

    fn wait(
        &self,
        request: WaitRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        self.call(SandboxEndpointOperation::Wait, || {
            self.inner.wait(request, cancellation)
        })
    }

    fn copy_to(
        &self,
        request: &CopyToRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        let result = self.call(SandboxEndpointOperation::CopyTo, || {
            self.inner.copy_to(request, cancellation)
        });
        if result.is_ok() {
            self.metrics
                .endpoint_bytes
                .get_or_create(&DirectionLabels {
                    direction: "copy_to",
                })
                .inc_by(saturating_u64(request.content().len()));
        }
        result
    }

    fn copy_from(
        &self,
        request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        let result = self.call(SandboxEndpointOperation::CopyFrom, || {
            self.inner.copy_from(request, cancellation)
        });
        if let Ok(bytes) = &result {
            self.metrics
                .endpoint_bytes
                .get_or_create(&DirectionLabels {
                    direction: "copy_from",
                })
                .inc_by(saturating_u64(bytes.len()));
        }
        result
    }
}

const fn provider_operation_label(value: SandboxProviderOperation) -> &'static str {
    match value {
        SandboxProviderOperation::Create => "create",
        SandboxProviderOperation::Attach => "attach",
        SandboxProviderOperation::Inspect => "inspect",
        SandboxProviderOperation::ServiceBindings => "service_bindings",
        SandboxProviderOperation::Destroy => "destroy",
    }
}

const fn endpoint_operation_label(value: SandboxEndpointOperation) -> &'static str {
    match value {
        SandboxEndpointOperation::Exec => "exec",
        SandboxEndpointOperation::Signal => "signal",
        SandboxEndpointOperation::Wait => "wait",
        SandboxEndpointOperation::CopyTo => "copy_to",
        SandboxEndpointOperation::CopyFrom => "copy_from",
    }
}

const fn provider_outcome_label(value: ProviderErrorKind) -> &'static str {
    match value {
        ProviderErrorKind::Cancelled => "cancelled",
        ProviderErrorKind::TimedOut => "timed_out",
        _ => "error",
    }
}

const fn endpoint_outcome_label(value: ExecutionErrorKind) -> &'static str {
    match value {
        ExecutionErrorKind::Cancelled => "cancelled",
        ExecutionErrorKind::TimedOut => "timed_out",
        _ => "error",
    }
}

const fn provider_error_label(value: ProviderErrorKind) -> &'static str {
    match value {
        ProviderErrorKind::UnsupportedPlatform => "unsupported_platform",
        ProviderErrorKind::UnsupportedCapability => "unsupported_capability",
        ProviderErrorKind::Cancelled => "cancelled",
        ProviderErrorKind::TimedOut => "timed_out",
        ProviderErrorKind::AdapterUnavailable => "adapter_unavailable",
        ProviderErrorKind::InvalidConfiguration => "invalid_configuration",
        ProviderErrorKind::NotFound => "not_found",
        ProviderErrorKind::Conflict => "conflict",
        ProviderErrorKind::OwnershipMismatch => "ownership_mismatch",
        ProviderErrorKind::InvalidState => "invalid_state",
        ProviderErrorKind::OutputLimitExceeded => "output_limit_exceeded",
        ProviderErrorKind::BackendRejected => "backend_rejected",
        ProviderErrorKind::LocalStorage => "local_storage",
    }
}

const fn endpoint_error_label(value: ExecutionErrorKind) -> &'static str {
    match value {
        ExecutionErrorKind::UnsupportedCapability => "unsupported_capability",
        ExecutionErrorKind::InvalidEnvironment => "invalid_environment",
        ExecutionErrorKind::Cancelled => "cancelled",
        ExecutionErrorKind::TimedOut => "timed_out",
        ExecutionErrorKind::NotFound => "not_found",
        ExecutionErrorKind::OwnershipMismatch => "ownership_mismatch",
        ExecutionErrorKind::InvalidState => "invalid_state",
        ExecutionErrorKind::OutputLimitExceeded => "output_limit_exceeded",
        ExecutionErrorKind::BackendRejected => "backend_rejected",
        ExecutionErrorKind::LocalStorage => "local_storage",
    }
}

const fn execution_termination_label(value: ExecutionTermination) -> &'static str {
    match value {
        ExecutionTermination::Exited(_) => "exited",
        ExecutionTermination::Signalled => "signalled",
        ExecutionTermination::TimedOut => "timed_out",
        ExecutionTermination::Cancelled => "cancelled",
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct StageLabels {
    stage: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RouteLabels {
    route: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RouteOutcomeLabels {
    route: &'static str,
    outcome: &'static str,
}

#[derive(Clone)]
struct PodmanMetrics {
    commands: Family<StageLabels, Counter>,
    command_outcomes: Family<OutcomeLabels, Counter>,
    command_duration: Histogram,
    commands_in_flight: Gauge,
    command_output_bytes: Family<DirectionLabels, Counter>,
    docker_requests: Family<RouteOutcomeLabels, Counter>,
    docker_duration: Histogram,
    docker_in_flight: Family<RouteLabels, Gauge>,
    docker_bytes: Family<DirectionLabels, Counter>,
    docker_rejections: Family<ReasonLabels, Counter>,
}

impl PodmanMetrics {
    fn register(registry: &mut Registry) -> Self {
        let commands = Family::<StageLabels, Counter>::default();
        registry.register(
            "runner_podman_commands",
            "Local Podman command invocations by typed provider or endpoint stage",
            commands.clone(),
        );
        let command_outcomes = Family::<OutcomeLabels, Counter>::default();
        registry.register(
            "runner_podman_command_outcomes",
            "Local Podman command outcomes across all typed stages",
            command_outcomes.clone(),
        );
        let command_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_podman_command_duration",
            "Local Podman command duration across all typed stages",
            Unit::Seconds,
            command_duration.clone(),
        );
        let commands_in_flight = Gauge::default();
        registry.register(
            "runner_podman_commands_in_flight",
            "Local Podman commands currently in flight",
            commands_in_flight.clone(),
        );
        let command_output_bytes = Family::<DirectionLabels, Counter>::default();
        registry.register_with_unit(
            "runner_podman_command_output",
            "Bounded stdout and stderr bytes returned by local Podman commands",
            Unit::Bytes,
            command_output_bytes.clone(),
        );

        let docker_requests = Family::<RouteOutcomeLabels, Counter>::default();
        registry.register(
            "runner_docker_proxy_requests",
            "Attempt-scoped Docker proxy requests by finite route and terminal proxy outcome",
            docker_requests.clone(),
        );
        let docker_duration = semantic_duration_histogram();
        registry.register_with_unit(
            "runner_docker_proxy_request_duration",
            "Attempt-scoped Docker proxy request duration across all routes",
            Unit::Seconds,
            docker_duration.clone(),
        );
        let docker_in_flight = Family::<RouteLabels, Gauge>::default();
        registry.register(
            "runner_docker_proxy_requests_in_flight",
            "Attempt-scoped Docker proxy requests in flight by finite route",
            docker_in_flight.clone(),
        );
        let docker_bytes = Family::<DirectionLabels, Counter>::default();
        registry.register_with_unit(
            "runner_docker_proxy",
            "Complete request and response payload bytes crossing the Docker proxy",
            Unit::Bytes,
            docker_bytes.clone(),
        );
        let docker_rejections = Family::<ReasonLabels, Counter>::default();
        registry.register(
            "runner_docker_proxy_rejections",
            "Docker proxy requests or connections rejected by a finite boundary reason",
            docker_rejections.clone(),
        );

        let metrics = Self {
            commands,
            command_outcomes,
            command_duration,
            commands_in_flight,
            command_output_bytes,
            docker_requests,
            docker_duration,
            docker_in_flight,
            docker_bytes,
            docker_rejections,
        };
        metrics.preinitialize();
        metrics
    }

    fn preinitialize(&self) {
        for stage in [
            "provider_validate",
            "provider_create_workspace",
            "provider_create_network",
            "provider_create_sandbox",
            "provider_create_container",
            "provider_start",
            "provider_attach",
            "provider_inspect",
            "provider_verify_ownership",
            "provider_destroy_container",
            "provider_destroy_sandbox",
            "provider_destroy_network",
            "provider_destroy_workspace",
            "endpoint_exec",
            "endpoint_signal",
            "endpoint_wait",
            "endpoint_copy_to",
            "endpoint_copy_from",
        ] {
            self.commands
                .get_or_create(&StageLabels { stage })
                .inc_by(0);
        }
        for outcome in [
            "success",
            "nonzero_exit",
            "signalled",
            "timed_out",
            "cancelled",
            "failed_to_start",
            "input_incomplete",
            "output_truncated",
        ] {
            self.command_outcomes
                .get_or_create(&OutcomeLabels { outcome })
                .inc_by(0);
        }
        for direction in ["stdout", "stderr"] {
            self.command_output_bytes
                .get_or_create(&DirectionLabels { direction })
                .inc_by(0);
        }
        for route in [
            "ping",
            "version",
            "build",
            "image_inspect",
            "image_delete",
            "container_create",
            "container_inspect",
            "container_operation",
        ] {
            self.docker_in_flight
                .get_or_create(&RouteLabels { route })
                .set(0);
            for outcome in ["forwarded", "rejected", "io_error"] {
                self.docker_requests
                    .get_or_create(&RouteOutcomeLabels { route, outcome })
                    .inc_by(0);
            }
        }
        for direction in ["request", "response"] {
            self.docker_bytes
                .get_or_create(&DirectionLabels { direction })
                .inc_by(0);
        }
        for reason in [
            "connection_limit",
            "malformed_head",
            "unsupported_transfer",
            "request_too_large",
            "policy",
            "worker_unavailable",
        ] {
            self.docker_rejections
                .get_or_create(&ReasonLabels { reason })
                .inc_by(0);
        }
    }

    fn observe(&self, event: PodmanEvent) {
        match event {
            PodmanEvent::CommandStarted { .. } => {
                self.commands_in_flight.inc();
            }
            PodmanEvent::CommandCompleted {
                stage,
                outcome,
                duration,
                stdout_bytes,
                stderr_bytes,
            } => {
                self.commands_in_flight.dec();
                self.commands
                    .get_or_create(&StageLabels {
                        stage: podman_stage_label(stage),
                    })
                    .inc();
                self.command_outcomes
                    .get_or_create(&OutcomeLabels {
                        outcome: podman_command_outcome_label(outcome),
                    })
                    .inc();
                self.command_duration.observe(duration.as_secs_f64());
                self.command_output_bytes
                    .get_or_create(&DirectionLabels {
                        direction: "stdout",
                    })
                    .inc_by(stdout_bytes);
                self.command_output_bytes
                    .get_or_create(&DirectionLabels {
                        direction: "stderr",
                    })
                    .inc_by(stderr_bytes);
            }
            PodmanEvent::DockerRequestStarted { route } => {
                self.docker_in_flight
                    .get_or_create(&RouteLabels {
                        route: docker_route_label(route),
                    })
                    .inc();
            }
            PodmanEvent::DockerRequestCompleted {
                route,
                outcome,
                duration,
                request_bytes,
                response_bytes,
            } => {
                let route = docker_route_label(route);
                self.docker_in_flight
                    .get_or_create(&RouteLabels { route })
                    .dec();
                self.docker_requests
                    .get_or_create(&RouteOutcomeLabels {
                        route,
                        outcome: docker_outcome_label(outcome),
                    })
                    .inc();
                self.docker_duration.observe(duration.as_secs_f64());
                self.docker_bytes
                    .get_or_create(&DirectionLabels {
                        direction: "request",
                    })
                    .inc_by(request_bytes);
                self.docker_bytes
                    .get_or_create(&DirectionLabels {
                        direction: "response",
                    })
                    .inc_by(response_bytes);
            }
            PodmanEvent::DockerRejected { reason } => {
                self.docker_rejections
                    .get_or_create(&ReasonLabels {
                        reason: docker_rejection_label(reason),
                    })
                    .inc();
            }
        }
    }
}

impl PodmanObserver for RunnerMetrics {
    fn observe(&self, event: PodmanEvent) {
        self.podman.observe(event);
    }
}

const fn podman_stage_label(value: PodmanCommandStage) -> &'static str {
    match value {
        PodmanCommandStage::Provider(ProviderStage::Validate) => "provider_validate",
        PodmanCommandStage::Provider(ProviderStage::CreateWorkspace) => "provider_create_workspace",
        PodmanCommandStage::Provider(ProviderStage::CreateNetwork) => "provider_create_network",
        PodmanCommandStage::Provider(ProviderStage::CreateSandbox) => "provider_create_sandbox",
        PodmanCommandStage::Provider(ProviderStage::CreateContainer) => "provider_create_container",
        PodmanCommandStage::Provider(ProviderStage::Start) => "provider_start",
        PodmanCommandStage::Provider(ProviderStage::Attach) => "provider_attach",
        PodmanCommandStage::Provider(ProviderStage::Inspect) => "provider_inspect",
        PodmanCommandStage::Provider(ProviderStage::VerifyOwnership) => "provider_verify_ownership",
        PodmanCommandStage::Provider(ProviderStage::DestroyContainer) => {
            "provider_destroy_container"
        }
        PodmanCommandStage::Provider(ProviderStage::DestroySandbox) => "provider_destroy_sandbox",
        PodmanCommandStage::Provider(ProviderStage::DestroyNetwork) => "provider_destroy_network",
        PodmanCommandStage::Provider(ProviderStage::DestroyWorkspace) => {
            "provider_destroy_workspace"
        }
        PodmanCommandStage::Endpoint(ExecutionStage::Exec) => "endpoint_exec",
        PodmanCommandStage::Endpoint(ExecutionStage::Signal) => "endpoint_signal",
        PodmanCommandStage::Endpoint(ExecutionStage::Wait) => "endpoint_wait",
        PodmanCommandStage::Endpoint(ExecutionStage::CopyTo) => "endpoint_copy_to",
        PodmanCommandStage::Endpoint(ExecutionStage::CopyFrom) => "endpoint_copy_from",
    }
}

const fn podman_command_outcome_label(value: PodmanCommandOutcome) -> &'static str {
    match value {
        PodmanCommandOutcome::Success => "success",
        PodmanCommandOutcome::NonzeroExit => "nonzero_exit",
        PodmanCommandOutcome::Signalled => "signalled",
        PodmanCommandOutcome::TimedOut => "timed_out",
        PodmanCommandOutcome::Cancelled => "cancelled",
        PodmanCommandOutcome::FailedToStart => "failed_to_start",
        PodmanCommandOutcome::InputIncomplete => "input_incomplete",
        PodmanCommandOutcome::OutputTruncated => "output_truncated",
    }
}

const fn docker_route_label(value: DockerProxyRoute) -> &'static str {
    match value {
        DockerProxyRoute::Ping => "ping",
        DockerProxyRoute::Version => "version",
        DockerProxyRoute::Build => "build",
        DockerProxyRoute::ImageInspect => "image_inspect",
        DockerProxyRoute::ImageDelete => "image_delete",
        DockerProxyRoute::ContainerCreate => "container_create",
        DockerProxyRoute::ContainerInspect => "container_inspect",
        DockerProxyRoute::ContainerOperation => "container_operation",
    }
}

const fn docker_outcome_label(value: DockerProxyOutcome) -> &'static str {
    match value {
        DockerProxyOutcome::Forwarded => "forwarded",
        DockerProxyOutcome::Rejected => "rejected",
        DockerProxyOutcome::IoError => "io_error",
    }
}

const fn docker_rejection_label(value: DockerProxyRejection) -> &'static str {
    match value {
        DockerProxyRejection::ConnectionLimit => "connection_limit",
        DockerProxyRejection::MalformedHead => "malformed_head",
        DockerProxyRejection::UnsupportedTransfer => "unsupported_transfer",
        DockerProxyRejection::RequestTooLarge => "request_too_large",
        DockerProxyRejection::Policy => "policy",
        DockerProxyRejection::WorkerUnavailable => "worker_unavailable",
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SlotState {
    Idle,
    Leased,
    Preparing,
    Running,
    Cancelling,
    Finalizing,
    Terminal,
}

impl SlotState {
    const ALL: [Self; 7] = [
        Self::Idle,
        Self::Leased,
        Self::Preparing,
        Self::Running,
        Self::Cancelling,
        Self::Finalizing,
        Self::Terminal,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Idle => 0,
            Self::Leased => 1,
            Self::Preparing => 2,
            Self::Running => 3,
            Self::Cancelling => 4,
            Self::Finalizing => 5,
            Self::Terminal => 6,
        }
    }

    const fn from_lifecycle(lifecycle: JobLifecycle) -> Self {
        match lifecycle {
            JobLifecycle::Queued | JobLifecycle::Leased => Self::Leased,
            JobLifecycle::Preparing => Self::Preparing,
            JobLifecycle::Running => Self::Running,
            JobLifecycle::Cancelling => Self::Cancelling,
            JobLifecycle::Finalizing => Self::Finalizing,
            JobLifecycle::Succeeded
            | JobLifecycle::Failed
            | JobLifecycle::Cancelled
            | JobLifecycle::TimedOut
            | JobLifecycle::Skipped
            | JobLifecycle::Lost => Self::Terminal,
        }
    }
}

impl EncodeLabelValue for SlotState {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        encoder.write_str(match self {
            Self::Idle => "idle",
            Self::Leased => "leased",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Cancelling => "cancelling",
            Self::Finalizing => "finalizing",
            Self::Terminal => "terminal",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct SlotStateLabels {
    state: SlotState,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum PendingDelivery {
    TerminalResult,
    LeaseRejection,
    LogStream,
}

impl PendingDelivery {
    const ALL: [Self; 3] = [Self::TerminalResult, Self::LeaseRejection, Self::LogStream];

    const fn index(self) -> usize {
        match self {
            Self::TerminalResult => 0,
            Self::LeaseRejection => 1,
            Self::LogStream => 2,
        }
    }
}

impl EncodeLabelValue for PendingDelivery {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        encoder.write_str(match self {
            Self::TerminalResult => "terminal_result",
            Self::LeaseRejection => "lease_rejection",
            Self::LogStream => "log_stream",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct DeliveryLabels {
    kind: PendingDelivery,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SnapshotOutcome {
    Success,
    JournalError,
    SpoolError,
    BothError,
}

impl SnapshotOutcome {
    const ALL: [Self; 4] = [
        Self::Success,
        Self::JournalError,
        Self::SpoolError,
        Self::BothError,
    ];
}

impl EncodeLabelValue for SnapshotOutcome {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        encoder.write_str(match self {
            Self::Success => "success",
            Self::JournalError => "journal_error",
            Self::SpoolError => "spool_error",
            Self::BothError => "both_error",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct SnapshotOutcomeLabels {
    outcome: SnapshotOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublishedSlotSnapshot {
    journal_slots: u64,
    slots: [u64; 7],
}

#[derive(Debug)]
struct SlotSnapshotCollector {
    configured_slots: u64,
    published: Mutex<PublishedSlotSnapshot>,
}

impl SlotSnapshotCollector {
    fn new(configured_slots: u64) -> Self {
        let mut slots = [0; 7];
        slots[SlotState::Idle.index()] = configured_slots;
        Self {
            configured_slots,
            published: Mutex::new(PublishedSlotSnapshot {
                journal_slots: 0,
                slots,
            }),
        }
    }

    fn publish(&self, journal_slots: u64, slots: [u64; 7]) {
        *self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = PublishedSlotSnapshot {
            journal_slots,
            slots,
        };
    }

    fn snapshot(&self) -> PublishedSlotSnapshot {
        *self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Collector for SlotSnapshotCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        let published = self.snapshot();
        encode_const_gauge(
            &mut encoder,
            "runner_slots_configured",
            "Configured maximum parallel runner slots",
            self.configured_slots,
        )?;

        let slots = Family::<SlotStateLabels, Gauge>::default();
        for state in SlotState::ALL {
            slots
                .get_or_create(&SlotStateLabels { state })
                .set(saturating_i64(published.slots[state.index()]));
        }
        let slot_encoder = encoder.encode_descriptor(
            "runner_slots",
            "Aggregate configured and retained durable runner slots by finite local state",
            None,
            MetricType::Gauge,
        )?;
        slots.encode(slot_encoder)?;

        encode_const_gauge(
            &mut encoder,
            "runner_slots_over_capacity",
            "Durable journal slots exceeding the runner's current configured capacity",
            published
                .journal_slots
                .saturating_sub(self.configured_slots),
        )?;
        let state_total = published
            .slots
            .iter()
            .copied()
            .fold(0_u64, u64::saturating_add);
        encode_const_gauge(
            &mut encoder,
            "runner_slot_snapshot_conserved",
            "Whether this atomically published slot snapshot totals max(configured slots, durable slots)",
            u64::from(state_total == self.configured_slots.max(published.journal_slots)),
        )?;
        encode_const_gauge(
            &mut encoder,
            "runner_journal_slots",
            "Durable execution slots retained by the in-memory runner journal snapshot",
            published.journal_slots,
        )
    }
}

fn encode_const_gauge(
    encoder: &mut DescriptorEncoder<'_>,
    name: &'static str,
    help: &'static str,
    value: u64,
) -> Result<(), fmt::Error> {
    let gauge = ConstGauge::new(saturating_i64(value));
    let metric_encoder = encoder.encode_descriptor(name, help, None, MetricType::Gauge)?;
    gauge.encode(metric_encoder)
}

#[derive(Clone)]
struct SnapshotMetrics {
    configured_slots: u64,
    journal_session_present: Gauge,
    slot_snapshot: Arc<SlotSnapshotCollector>,
    journal_revision: Gauge,
    earliest_lease_expiry_seconds: Gauge,
    journal_poisoned: Gauge,
    spool_poisoned: Gauge,
    spool_objects: Gauge,
    spool_protected_bytes: Gauge,
    spool_max_objects: Gauge,
    spool_max_bytes: Gauge,
    pending_deliveries: Family<DeliveryLabels, Gauge>,
    pending_delivery_oldest_timestamp: Family<DeliveryLabels, Gauge>,
    pending_log_frames: Gauge,
    pending_log_bytes: Gauge,
    pending_provider_operations: Gauge,
    orphan_slots: Gauge,
    sandboxes: Gauge,
    refreshes: Family<SnapshotOutcomeLabels, Counter>,
    refresh_duration: Histogram,
    refresh_healthy: Gauge,
    last_success_seconds: Gauge,
}

impl SnapshotMetrics {
    #[allow(clippy::too_many_lines)] // One declarative schema keeps names, help, units, and handles auditable together.
    fn register(registry: &mut Registry, configured_slots: u16) -> Self {
        let slot_snapshot = Arc::new(SlotSnapshotCollector::new(u64::from(configured_slots)));
        registry.register_collector(Box::new(Arc::clone(&slot_snapshot)));
        let journal_session_present = register_gauge(
            registry,
            "runner_journal_session_present",
            "Whether a resumable session binding is present in the in-memory journal snapshot",
        );

        let pending_deliveries = Family::<DeliveryLabels, Gauge>::default();
        registry.register(
            "runner_pending_deliveries",
            "Durable runner-to-control deliveries not yet acknowledged or authorized abandoned",
            pending_deliveries.clone(),
        );
        for kind in PendingDelivery::ALL {
            pending_deliveries
                .get_or_create(&DeliveryLabels { kind })
                .set(0);
        }
        let pending_delivery_oldest_timestamp = Family::<DeliveryLabels, Gauge>::default();
        registry.register_with_unit(
            "runner_pending_delivery_oldest_timestamp",
            "Unix timestamp of the oldest durable unacknowledged runner-to-control delivery by bounded kind, or zero",
            Unit::Seconds,
            pending_delivery_oldest_timestamp.clone(),
        );
        for kind in PendingDelivery::ALL {
            pending_delivery_oldest_timestamp
                .get_or_create(&DeliveryLabels { kind })
                .set(0);
        }

        let refreshes = Family::<SnapshotOutcomeLabels, Counter>::default();
        registry.register(
            "runner_snapshot_refreshes",
            "In-memory journal and protected-spool snapshot refreshes by outcome",
            refreshes.clone(),
        );
        for outcome in SnapshotOutcome::ALL {
            refreshes
                .get_or_create(&SnapshotOutcomeLabels { outcome })
                .inc_by(0);
        }

        let refresh_duration =
            classic_and_native_histogram([0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.05, 0.1]);
        registry.register_with_unit(
            "runner_snapshot_refresh_duration",
            "Time spent cloning bounded in-memory journal and spool snapshots",
            Unit::Seconds,
            refresh_duration.clone(),
        );

        Self {
            configured_slots: u64::from(configured_slots),
            journal_session_present,
            slot_snapshot,
            journal_revision: register_gauge(
                registry,
                "runner_journal_revision",
                "Latest successfully sampled in-memory runner journal revision",
            ),
            earliest_lease_expiry_seconds: {
                let metric = Gauge::default();
                registry.register_with_unit(
                    "runner_lease_earliest_expiry_timestamp",
                    "Earliest active accepted lease expiry in the latest in-memory journal snapshot, or zero",
                    Unit::Seconds,
                    metric.clone(),
                );
                metric
            },
            journal_poisoned: register_gauge(
                registry,
                "runner_journal_poisoned",
                "Whether the runner journal rejected its latest snapshot as poisoned",
            ),
            spool_poisoned: register_gauge(
                registry,
                "runner_spool_poisoned",
                "Whether the protected spool rejected its latest usage snapshot as poisoned",
            ),
            spool_objects: register_gauge(
                registry,
                "runner_spool_objects",
                "Protected immutable objects in the latest in-memory spool usage snapshot",
            ),
            spool_protected_bytes: {
                let metric = Gauge::default();
                registry.register_with_unit(
                    "runner_spool_protected",
                    "Protected bytes in the latest in-memory spool usage snapshot",
                    Unit::Bytes,
                    metric.clone(),
                );
                metric
            },
            spool_max_objects: register_gauge(
                registry,
                "runner_spool_max_objects",
                "Configured protected spool object limit",
            ),
            spool_max_bytes: {
                let metric = Gauge::default();
                registry.register_with_unit(
                    "runner_spool_max",
                    "Configured protected spool byte limit",
                    Unit::Bytes,
                    metric.clone(),
                );
                metric
            },
            pending_deliveries,
            pending_delivery_oldest_timestamp,
            pending_log_frames: register_gauge(
                registry,
                "runner_pending_log_frames",
                "Produced log frames not yet acknowledged by the control plane",
            ),
            pending_log_bytes: {
                let metric = Gauge::default();
                registry.register_with_unit(
                    "runner_pending_log",
                    "Logical log-spool bytes not yet compacted after acknowledgement",
                    Unit::Bytes,
                    metric.clone(),
                );
                metric
            },
            pending_provider_operations: register_gauge(
                registry,
                "runner_pending_provider_operations",
                "Durable provider operations with pending or uncertain outcome",
            ),
            orphan_slots: register_gauge(
                registry,
                "runner_orphan_slots",
                "Durable slots awaiting or retaining orphan reconciliation authority",
            ),
            sandboxes: register_gauge(
                registry,
                "runner_sandboxes",
                "Aggregate live sandbox identities retained by the in-memory journal snapshot",
            ),
            refreshes,
            refresh_duration,
            refresh_healthy: register_gauge(
                registry,
                "runner_snapshot_refresh_healthy",
                "Whether both journal and spool snapshots succeeded on the latest refresh",
            ),
            last_success_seconds: {
                let metric = Gauge::default();
                registry.register_with_unit(
                    "runner_snapshot_last_success_timestamp",
                    "Unix timestamp of the latest successful journal and spool snapshot refresh",
                    Unit::Seconds,
                    metric.clone(),
                );
                metric
            },
        }
        .with_journal_limits(registry)
    }

    fn with_journal_limits(self, registry: &mut Registry) -> Self {
        let maximum_slots = register_gauge(
            registry,
            "runner_journal_max_slots",
            "Hard maximum durable slots supported by the runner journal schema",
        );
        maximum_slots.set(saturating_i64(
            u64::try_from(MAX_JOURNALED_SLOTS).unwrap_or(u64::MAX),
        ));
        let maximum_bytes: Gauge = Gauge::default();
        maximum_bytes.set(saturating_i64(
            u64::try_from(MAX_JOURNAL_BYTES).unwrap_or(u64::MAX),
        ));
        registry.register_with_unit(
            "runner_journal_max",
            "Hard encoded runner journal byte limit",
            Unit::Bytes,
            maximum_bytes,
        );
        self
    }

    fn refresh(&self, journal: &FileJournal, spool: &FileSpool) {
        let started = Instant::now();
        let journal_result = journal.snapshot();
        let spool_result = spool.usage();
        let limits = spool.limits();
        self.spool_max_objects.set(i64::from(limits.max_objects()));
        self.spool_max_bytes
            .set(saturating_i64(limits.max_total_bytes()));

        if let Ok(snapshot) = &journal_result {
            self.apply_journal(SnapshotCounts::from_journal(
                snapshot,
                self.configured_slots,
            ));
            self.journal_poisoned.set(0);
        } else {
            self.journal_poisoned.set(i64::from(
                journal_result
                    .as_ref()
                    .is_err_and(|error| matches!(error, JournalError::Poisoned)),
            ));
        }
        if let Ok((objects, protected_bytes)) = &spool_result {
            self.spool_objects.set(i64::from(*objects));
            self.spool_protected_bytes
                .set(saturating_i64(*protected_bytes));
            self.spool_poisoned.set(0);
        } else {
            self.spool_poisoned.set(i64::from(
                spool_result
                    .as_ref()
                    .is_err_and(|error| matches!(error, SpoolError::Poisoned)),
            ));
        }

        let outcome = match (journal_result.is_ok(), spool_result.is_ok()) {
            (true, true) => SnapshotOutcome::Success,
            (false, true) => SnapshotOutcome::JournalError,
            (true, false) => SnapshotOutcome::SpoolError,
            (false, false) => SnapshotOutcome::BothError,
        };
        self.refreshes
            .get_or_create(&SnapshotOutcomeLabels { outcome })
            .inc();
        self.refresh_duration
            .observe(started.elapsed().as_secs_f64());
        let healthy = outcome == SnapshotOutcome::Success;
        self.refresh_healthy.set(i64::from(healthy));
        if healthy {
            self.last_success_seconds.set(unix_timestamp_seconds());
        }
    }

    fn apply_journal(&self, counts: SnapshotCounts) {
        self.journal_session_present
            .set(i64::from(counts.journal_session_present));
        self.journal_revision
            .set(saturating_i64(counts.journal_revision));
        self.slot_snapshot
            .publish(counts.journal_slots, counts.slots);
        self.earliest_lease_expiry_seconds
            .set(counts.earliest_lease_expiry_seconds.unwrap_or(0));
        for (kind, count) in [
            (PendingDelivery::TerminalResult, counts.terminal_results),
            (PendingDelivery::LeaseRejection, counts.lease_rejections),
            (PendingDelivery::LogStream, counts.log_streams),
        ] {
            self.pending_deliveries
                .get_or_create(&DeliveryLabels { kind })
                .set(saturating_i64(count));
            self.pending_delivery_oldest_timestamp
                .get_or_create(&DeliveryLabels { kind })
                .set(counts.pending_delivery_oldest_seconds[kind.index()].unwrap_or(0));
        }
        self.pending_log_frames
            .set(saturating_i64(counts.log_frames));
        self.pending_log_bytes.set(saturating_i64(counts.log_bytes));
        self.pending_provider_operations
            .set(saturating_i64(counts.provider_operations));
        self.orphan_slots.set(saturating_i64(counts.orphan_slots));
        self.sandboxes.set(saturating_i64(counts.sandboxes));
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SnapshotCounts {
    journal_session_present: bool,
    journal_revision: u64,
    journal_slots: u64,
    slots: [u64; 7],
    earliest_lease_expiry_seconds: Option<i64>,
    terminal_results: u64,
    lease_rejections: u64,
    log_streams: u64,
    pending_delivery_oldest_seconds: [Option<i64>; 3],
    log_frames: u64,
    log_bytes: u64,
    provider_operations: u64,
    orphan_slots: u64,
    sandboxes: u64,
}

impl SnapshotCounts {
    fn from_journal(snapshot: &JournalSnapshot, configured_slots: u64) -> Self {
        let pending_delivery_timestamps = snapshot.pending_delivery_timestamps();
        let mut counts = Self {
            journal_session_present: snapshot.session().is_some(),
            journal_revision: snapshot.revision(),
            journal_slots: saturating_u64(snapshot.slots().len()),
            pending_delivery_oldest_seconds: [
                pending_delivery_timestamps
                    .terminal_result()
                    .map(|timestamp| timestamp.get().div_euclid(1_000)),
                pending_delivery_timestamps
                    .lease_rejection()
                    .map(|timestamp| timestamp.get().div_euclid(1_000)),
                pending_delivery_timestamps
                    .log_stream()
                    .map(|timestamp| timestamp.get().div_euclid(1_000)),
            ],
            ..Self::default()
        };
        counts.slots[SlotState::Idle.index()] =
            configured_slots.saturating_sub(saturating_u64(snapshot.slots().len()));
        for slot in snapshot.slots() {
            let state = SlotState::from_lifecycle(slot.lifecycle());
            counts.slots[state.index()] = counts.slots[state.index()].saturating_add(1);
            if slot.offer_status() == LeaseOfferStatus::Accepted
                && !slot.lifecycle().is_terminal()
                && slot.orphan().is_none()
            {
                let expiry_seconds = slot.expires_at().get().div_euclid(1_000);
                counts.earliest_lease_expiry_seconds = Some(
                    counts
                        .earliest_lease_expiry_seconds
                        .map_or(expiry_seconds, |current| current.min(expiry_seconds)),
                );
            }
            counts.sandboxes = counts
                .sandboxes
                .saturating_add(u64::from(slot.sandbox().is_some()));
            counts.orphan_slots = counts
                .orphan_slots
                .saturating_add(u64::from(slot.orphan().is_some()));
            counts.provider_operations = counts.provider_operations.saturating_add(saturating_u64(
                slot.provider_operations()
                    .iter()
                    .filter(|operation| operation.is_pending())
                    .count(),
            ));

            let orphan = slot.orphan();
            if slot.terminal_result().is_some_and(|result| {
                !result.is_acknowledged()
                    && orphan.is_none_or(|record| {
                        record.abandonment(OrphanDelivery::TerminalResult).is_none()
                    })
            }) {
                counts.terminal_results = counts.terminal_results.saturating_add(1);
            }
            if slot.rejection().is_some_and(|rejection| {
                !rejection.is_response_acknowledged()
                    && orphan.is_none_or(|record| {
                        record.abandonment(OrphanDelivery::LeaseRejection).is_none()
                    })
            }) {
                counts.lease_rejections = counts.lease_rejections.saturating_add(1);
            }
            if let Some(log) = slot.log_delivery()
                && !log.is_fully_delivered()
                && orphan
                    .is_none_or(|record| record.abandonment(OrphanDelivery::LogStream).is_none())
            {
                counts.log_streams = counts.log_streams.saturating_add(1);
                counts.log_bytes = counts.log_bytes.saturating_add(log.backlog_content_bytes());
                let produced = log
                    .produced_through()
                    .map_or(0, |sequence| sequence.get().saturating_add(1));
                let acknowledged = log
                    .acknowledged_through()
                    .map_or(0, |sequence| sequence.get().saturating_add(1));
                counts.log_frames = counts
                    .log_frames
                    .saturating_add(produced.saturating_sub(acknowledged));
            }
        }
        counts
    }
}

fn unix_timestamp_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| saturating_i64(duration.as_secs()))
}

fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[allow(clippy::cast_precision_loss)]
fn milliseconds_as_seconds(value: i64) -> f64 {
    value as f64 / 1_000.0
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use automata_ci_execution::{
        CopyFromRequest, CopyToRequest, ExecutionArgv, ExecutionCommand, ExecutionEnvironment,
        ExecutionSignal, NeverCancelled, OperationId, OperationOutcome, ProviderCapabilities,
        ProviderError, ProviderErrorKind, ProviderId, ProviderStage, RunnerId, SandboxCapability,
        SandboxCustody, SandboxGeneration, SandboxHandle, SignalRequest, TargetPath, WaitRequest,
    };
    use prometheus_client::encoding::prometheus_protobuf;

    use super::*;

    #[test]
    fn production_histogram_preserves_classic_buckets_and_exports_native_spans() {
        let mut registry = Registry::default();
        let metrics = SnapshotMetrics::register(&mut registry, 2);
        metrics.refresh_duration.observe(0.005);

        let families = prometheus_protobuf::encode(&registry).expect("protobuf encoding");
        let family = families
            .iter()
            .find(|family| family.name == "runner_snapshot_refresh_duration_seconds")
            .expect("production snapshot-refresh histogram family");
        let histogram = family
            .metric
            .first()
            .and_then(|metric| metric.histogram.as_ref())
            .expect("histogram sample");

        assert_eq!(histogram.sample_count, 1);
        assert_eq!(histogram.sample_sum.to_bits(), 0.005_f64.to_bits());
        assert_eq!(histogram.schema, 3);
        assert!(histogram.positive_span.iter().any(|span| span.length > 0));
        assert!(!histogram.positive_delta.is_empty());
        assert_eq!(
            histogram
                .bucket
                .iter()
                .map(|bucket| bucket.upper_bound)
                .collect::<Vec<_>>(),
            [0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.05, 0.1]
                .into_iter()
                .chain([f64::MAX])
                .collect::<Vec<_>>()
        );
    }

    #[derive(Debug)]
    struct TestSandboxProvider {
        provider_id: ProviderId,
        capabilities: ProviderCapabilities,
        handle: SandboxHandle,
    }

    impl TestSandboxProvider {
        fn new() -> Self {
            let provider_id = ProviderId::new("test-provider").expect("provider id");
            Self {
                handle: SandboxHandle::new(provider_id.clone(), "private-handle-sentinel")
                    .expect("sandbox handle"),
                provider_id,
                capabilities: ProviderCapabilities::new([
                    SandboxCapability::Attach,
                    SandboxCapability::Exec,
                    SandboxCapability::Signal,
                    SandboxCapability::Wait,
                    SandboxCapability::CopyTo,
                    SandboxCapability::CopyFrom,
                ])
                .expect("capabilities"),
            }
        }
    }

    impl SandboxProvider for TestSandboxProvider {
        fn provider_id(&self) -> &ProviderId {
            &self.provider_id
        }

        fn capabilities(&self) -> &ProviderCapabilities {
            &self.capabilities
        }

        fn create(
            &self,
            _spec: &SandboxSpec,
            _cancellation: &dyn Cancellation,
        ) -> Result<SandboxRecord, ProviderError> {
            Err(ProviderError::new(
                ProviderErrorKind::Cancelled,
                ProviderStage::CreateSandbox,
                OperationOutcome::KnownNoEffect,
                None,
            ))
        }

        fn attach(
            &self,
            _handle: &SandboxHandle,
            _cancellation: &dyn Cancellation,
        ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
            Ok(Box::new(TestExecutionEndpoint {
                handle: self.handle.clone(),
            }))
        }

        fn inspect(
            &self,
            _handle: &SandboxHandle,
            _cancellation: &dyn Cancellation,
        ) -> Result<SandboxInspection, ProviderError> {
            Err(ProviderError::new(
                ProviderErrorKind::TimedOut,
                ProviderStage::Inspect,
                OperationOutcome::KnownNoEffect,
                None,
            ))
        }

        fn service_bindings(
            &self,
            _handle: &SandboxHandle,
            _cancellation: &dyn Cancellation,
        ) -> Result<ServiceContainerBindings, ProviderError> {
            Ok(ServiceContainerBindings::empty())
        }

        fn destroy(
            &self,
            _request: &DestroySandbox,
            _cancellation: &dyn Cancellation,
        ) -> Result<DestroyDisposition, ProviderError> {
            Err(ProviderError::new(
                ProviderErrorKind::BackendRejected,
                ProviderStage::DestroySandbox,
                OperationOutcome::KnownNoEffect,
                None,
            ))
        }
    }

    #[derive(Debug)]
    struct TestExecutionEndpoint {
        handle: SandboxHandle,
    }

    impl ExecutionEndpoint for TestExecutionEndpoint {
        fn handle(&self) -> &SandboxHandle {
            &self.handle
        }

        fn capabilities(&self) -> &[SandboxCapability] {
            const CAPABILITIES: &[SandboxCapability] = &[
                SandboxCapability::Exec,
                SandboxCapability::Signal,
                SandboxCapability::Wait,
                SandboxCapability::CopyTo,
                SandboxCapability::CopyFrom,
            ];
            CAPABILITIES
        }

        fn exec(
            &self,
            _request: &ExecutionCommand,
            _cancellation: &dyn Cancellation,
        ) -> Result<ExecutionOutput, ExecutionError> {
            ExecutionOutput::new(
                ExecutionTermination::Exited(0),
                vec![
                    automata_ci_execution::ExecutionOutputRecord::data(
                        automata_ci_execution::ExecutionOutputStream::Stdout,
                        b"private-output-sentinel".to_vec(),
                    )
                    .expect("bounded stdout"),
                    automata_ci_execution::ExecutionOutputRecord::data(
                        automata_ci_execution::ExecutionOutputStream::Stderr,
                        b"stderr".to_vec(),
                    )
                    .expect("bounded stderr"),
                    automata_ci_execution::ExecutionOutputRecord::end_of_stream(
                        automata_ci_execution::ExecutionOutputStream::Stdout,
                    ),
                    automata_ci_execution::ExecutionOutputRecord::end_of_stream(
                        automata_ci_execution::ExecutionOutputStream::Stderr,
                    ),
                ],
                true,
            )
            .map_err(|_| {
                ExecutionError::new(
                    ExecutionErrorKind::OutputLimitExceeded,
                    ExecutionStage::Exec,
                )
            })
        }

        fn signal(
            &self,
            _request: SignalRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<(), ExecutionError> {
            Err(ExecutionError::new(
                ExecutionErrorKind::Cancelled,
                ExecutionStage::Signal,
            ))
        }

        fn wait(
            &self,
            _request: WaitRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<i32, ExecutionError> {
            Ok(0)
        }

        fn copy_to(
            &self,
            _request: &CopyToRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<(), ExecutionError> {
            Ok(())
        }

        fn copy_from(
            &self,
            _request: &CopyFromRequest,
            _cancellation: &dyn Cancellation,
        ) -> Result<Vec<u8>, ExecutionError> {
            Ok(b"private-copy-sentinel".to_vec())
        }
    }

    #[test]
    fn initial_series_are_bounded_closed_and_free_of_dynamic_identity() {
        let metrics = RunnerMetrics::new(4, None).expect("runner metrics registry");
        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("OpenMetrics exposition");
        let exposition = exposition.as_str();

        assert!(exposition.ends_with("# EOF\n"));
        assert!(exposition.contains("automata_ci_runner_slots{state=\"idle\"} 4"));
        for family in [
            "automata_ci_runner_ready ",
            "automata_ci_runner_control_requests_total{",
            "automata_ci_runner_control_request_duration_seconds_bucket{",
            "automata_ci_runner_control_requests_in_flight{",
            "automata_ci_runner_control_retries_total{",
            "automata_ci_runner_control_bytes_total{",
            "automata_ci_runner_control_last_success_timestamp_seconds ",
            "automata_ci_runner_control_server_clock_offset_seconds ",
            "automata_ci_runner_slots_configured ",
            "automata_ci_runner_session_connected ",
            "automata_ci_runner_journal_session_present ",
            "automata_ci_runner_slots_over_capacity ",
            "automata_ci_runner_slot_snapshot_conserved ",
            "automata_ci_runner_journal_slots ",
            "automata_ci_runner_lease_earliest_expiry_timestamp_seconds ",
            "automata_ci_runner_journal_max_slots ",
            "automata_ci_runner_journal_max_bytes ",
            "automata_ci_runner_spool_protected_bytes ",
            "automata_ci_runner_spool_max_bytes ",
            "automata_ci_runner_pending_deliveries{",
            "automata_ci_runner_pending_delivery_oldest_timestamp_seconds{",
            "automata_ci_runner_pending_log_bytes ",
            "automata_ci_runner_cgroup_cpu_usage_seconds_total ",
            "automata_ci_runner_cgroup_memory_current_bytes ",
            "automata_ci_runner_cgroup_io_bytes_total{",
            "automata_ci_runner_cgroup_snapshot_refreshes_total{",
            "automata_ci_runner_snapshot_refreshes_total{",
            "automata_ci_runner_snapshot_refresh_duration_seconds_bucket{",
            "automata_ci_runner_journal_mutations_total{",
            "automata_ci_runner_journal_mutation_duration_seconds_bucket{",
            "automata_ci_runner_journal_size_bytes ",
            "automata_ci_runner_spool_operations_total{",
            "automata_ci_runner_spool_failures_total{",
            "automata_ci_runner_sandbox_provider_operations_total{",
            "automata_ci_runner_sandbox_endpoint_operations_total{",
            "automata_ci_runner_podman_commands_total{",
            "automata_ci_runner_docker_proxy_requests_total{",
        ] {
            assert!(exposition.contains(family), "missing family: {family}");
        }
        for unit in [
            "# UNIT automata_ci_runner_control_request_duration_seconds seconds",
            "# UNIT automata_ci_runner_control_bytes bytes",
            "# UNIT automata_ci_runner_spool_protected_bytes bytes",
        ] {
            assert!(exposition.contains(unit), "missing unit metadata: {unit}");
        }
        for forbidden in [
            "runner_id=",
            "session_id=",
            "operation_id=",
            "attempt_id=",
            "lease_id=",
            "repository=",
            "path=",
            "error=",
            "secret-sentinel-value",
        ] {
            assert!(
                !exposition.contains(forbidden),
                "forbidden dynamic identity or text leaked: {forbidden}"
            );
        }
        let series = exposition
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .count();
        assert!(series < 1_000, "runner target exceeded its series budget");
    }

    #[test]
    fn runner_preinitialization_contains_only_reachable_label_tuples() {
        let metrics = RunnerMetrics::new(4, None).expect("runner metrics registry");
        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("OpenMetrics exposition");
        let exposition = exposition.as_str();
        for impossible in [
            "automata_ci_runner_commands_total{kind=\"lease_offer\",outcome=\"ignored_stale_lease\"}",
            "automata_ci_runner_commands_total{kind=\"cancellation\",outcome=\"ignored_invalid\"}",
            "automata_ci_runner_commands_total{kind=\"cancellation\",outcome=\"ignored_slot_unavailable\"}",
            "automata_ci_runner_session_handshakes_total{mode=\"fresh\",outcome=\"resumed\"}",
            "automata_ci_runner_control_remote_errors_total{kind=\"session\",disposition=\"retrying\"}",
            "automata_ci_runner_spool_operations_total{operation=\"persist\",outcome=\"already_absent\"}",
            "automata_ci_runner_spool_operations_total{operation=\"load\",outcome=\"already_absent\"}",
            "automata_ci_runner_spool_operations_total{operation=\"reconcile\",outcome=\"already_absent\"}",
        ] {
            assert!(
                !exposition.contains(impossible),
                "unreachable series was preinitialized: {impossible}"
            );
        }
    }

    #[test]
    fn semantic_duration_histograms_keep_the_reviewed_compact_buckets() {
        let metrics = RunnerMetrics::new(2, None).expect("runner metrics registry");
        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("OpenMetrics exposition");
        let buckets = exposition
            .as_str()
            .lines()
            .filter_map(|line| {
                line.strip_prefix("automata_ci_runner_cleanup_duration_seconds_bucket{le=\"")
                    .and_then(|suffix| suffix.split_once('"').map(|(bucket, _rest)| bucket))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            buckets,
            [
                "0.001", "0.005", "0.025", "0.1", "0.5", "1.0", "2.5", "10.0", "30.0", "+Inf",
            ]
        );
    }

    #[test]
    fn physical_control_observer_records_boundary_bytes_and_balances_in_flight() {
        let metrics = RunnerMetrics::new(2, None).expect("runner metrics registry");
        let observer = metrics.control_transport_observer();
        let in_flight = metrics.control.begin(ControlRequestKind::Handshake);

        observer.observe_bytes(RunnerControlClientByteDirection::Request, 123);
        observer.observe_bytes(RunnerControlClientByteDirection::Response, 45);
        let active = metrics
            .exporter()
            .encode_openmetrics()
            .expect("active OpenMetrics exposition");
        for expected in [
            "automata_ci_runner_control_requests_in_flight{kind=\"handshake\"} 1",
            "automata_ci_runner_control_bytes_total{direction=\"sent\"} 123",
            "automata_ci_runner_control_bytes_total{direction=\"received\"} 45",
        ] {
            assert!(active.as_str().contains(expected), "missing {expected}");
        }

        drop(in_flight);
        let completed = metrics
            .exporter()
            .encode_openmetrics()
            .expect("completed OpenMetrics exposition");
        assert!(
            completed
                .as_str()
                .contains("automata_ci_runner_control_requests_in_flight{kind=\"handshake\"} 0")
        );
    }

    #[test]
    fn synthetic_snapshot_updates_only_aggregate_gauges() {
        let metrics = RunnerMetrics::new(4, None).expect("runner metrics registry");
        let mut counts = SnapshotCounts {
            journal_session_present: true,
            journal_revision: 19,
            journal_slots: 2,
            earliest_lease_expiry_seconds: Some(42),
            terminal_results: 1,
            log_streams: 1,
            pending_delivery_oldest_seconds: [Some(11), None, Some(33)],
            log_frames: 3,
            log_bytes: 4_096,
            provider_operations: 2,
            orphan_slots: 1,
            sandboxes: 2,
            ..SnapshotCounts::default()
        };
        counts.slots[SlotState::Idle.index()] = 2;
        counts.slots[SlotState::Running.index()] = 1;
        counts.slots[SlotState::Terminal.index()] = 1;
        metrics.snapshot.apply_journal(counts);

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("OpenMetrics exposition");
        let exposition = exposition.as_str();
        for expected in [
            "automata_ci_runner_journal_session_present 1",
            "automata_ci_runner_journal_revision 19",
            "automata_ci_runner_lease_earliest_expiry_timestamp_seconds 42",
            "automata_ci_runner_slots{state=\"idle\"} 2",
            "automata_ci_runner_slots{state=\"running\"} 1",
            "automata_ci_runner_slots{state=\"terminal\"} 1",
            "automata_ci_runner_pending_deliveries{kind=\"terminal_result\"} 1",
            "automata_ci_runner_pending_delivery_oldest_timestamp_seconds{kind=\"terminal_result\"} 11",
            "automata_ci_runner_pending_delivery_oldest_timestamp_seconds{kind=\"lease_rejection\"} 0",
            "automata_ci_runner_pending_delivery_oldest_timestamp_seconds{kind=\"log_stream\"} 33",
            "automata_ci_runner_pending_log_frames 3",
            "automata_ci_runner_pending_log_bytes 4096",
            "automata_ci_runner_pending_provider_operations 2",
            "automata_ci_runner_orphan_slots 1",
            "automata_ci_runner_sandboxes 2",
        ] {
            assert!(exposition.contains(expected), "missing sample: {expected}");
        }
    }

    #[test]
    fn journal_observer_records_only_closed_physical_mutation_series() {
        let metrics = RunnerMetrics::new(2, None).expect("runner metrics registry");
        JournalObserver::observe_opened(&metrics, 321);
        JournalObserver::observe_mutation(
            &metrics,
            JournalMutationObservation::new(
                JournalMutationDomain::Log,
                JournalMutationOutcome::Committed,
                Duration::from_millis(7),
                Some(654),
            ),
        );
        JournalObserver::observe_mutation(
            &metrics,
            JournalMutationObservation::new(
                JournalMutationDomain::Lease,
                JournalMutationOutcome::Rejected,
                Duration::from_millis(2),
                None,
            ),
        );

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("OpenMetrics exposition");
        for expected in [
            "automata_ci_runner_journal_mutations_total{domain=\"log\",outcome=\"committed\"} 1",
            "automata_ci_runner_journal_mutations_total{domain=\"lease\",outcome=\"rejected\"} 1",
            "automata_ci_runner_journal_mutation_duration_seconds_count 2",
            "automata_ci_runner_journal_size_bytes 654",
        ] {
            assert!(
                exposition.as_str().contains(expected),
                "missing journal observation: {expected}"
            );
        }
    }

    #[test]
    fn lower_current_capacity_exports_explicit_durable_slot_overflow() {
        let metrics = RunnerMetrics::new(4, None).expect("runner metrics registry");
        let mut counts = SnapshotCounts {
            journal_slots: 6,
            ..SnapshotCounts::default()
        };
        counts.slots[SlotState::Running.index()] = 6;
        metrics.snapshot.apply_journal(counts);

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("OpenMetrics exposition");
        for expected in [
            "automata_ci_runner_slots{state=\"idle\"} 0",
            "automata_ci_runner_slots{state=\"running\"} 6",
            "automata_ci_runner_slots_over_capacity 2",
            "automata_ci_runner_slot_snapshot_conserved 1",
        ] {
            assert!(
                exposition.as_str().contains(expected),
                "missing overflow sample: {expected}"
            );
        }
    }

    #[test]
    fn semantic_observer_updates_only_closed_identifier_free_series() {
        let metrics = RunnerMetrics::new(2, None).expect("runner metrics registry");
        for event in [
            RunnerRuntimeEvent::SessionHandshake {
                mode: RuntimeSessionMode::Resume,
                outcome: RuntimeSessionOutcome::Resumed,
                duration: Duration::from_millis(25),
            },
            RunnerRuntimeEvent::SessionConnected {
                server_clock_offset_millis: 1_500,
            },
            RunnerRuntimeEvent::RetryBackoff {
                exchange: RuntimeExchangeKind::LogBatch,
                cause: RuntimeRetryCause::Unavailable,
                delay: Duration::from_millis(50),
            },
            RunnerRuntimeEvent::RetryAttempt {
                exchange: RuntimeExchangeKind::LogBatch,
            },
            RunnerRuntimeEvent::RemoteError {
                exchange: RuntimeExchangeKind::LeasePoll,
                kind: RuntimeRemoteErrorKind::RetryLater,
                disposition: RuntimeRemoteErrorDisposition::Retrying,
            },
            RunnerRuntimeEvent::Command {
                kind: RuntimeCommandKind::Cancellation,
                outcome: RuntimeCommandOutcome::Applied,
            },
            RunnerRuntimeEvent::JobCompleted {
                conclusion: RuntimeJobConclusion::Cancelled,
                duration: Some(Duration::from_secs(3)),
            },
            RunnerRuntimeEvent::LogBatchAcknowledged {
                frames: 3,
                bytes: 4_096,
                duration: Duration::from_millis(10),
            },
            RunnerRuntimeEvent::TerminalResult {
                stage: RuntimeTerminalResultStage::Acknowledged,
                conclusion: RuntimeJobConclusion::Cancelled,
            },
        ] {
            RunnerRuntimeObserver::observe(&metrics, event);
        }

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("OpenMetrics exposition");
        let exposition = exposition.as_str();
        for expected in [
            "automata_ci_runner_session_connected 1",
            "automata_ci_runner_control_server_clock_offset_seconds 1.5",
            "automata_ci_runner_session_handshakes_total{mode=\"resume\",outcome=\"resumed\"} 1",
            "automata_ci_runner_control_retry_backoffs_total{exchange=\"log_batch\",cause=\"unavailable\"} 1",
            "automata_ci_runner_control_retries_total{kind=\"log_batch\"} 1",
            "automata_ci_runner_control_remote_errors_total{kind=\"retry_later\",disposition=\"retrying\"} 1",
            "automata_ci_runner_commands_total{kind=\"cancellation\",outcome=\"applied\"} 1",
            "automata_ci_runner_jobs_completed_total{conclusion=\"cancelled\"} 1",
            "automata_ci_runner_log_batches_acknowledged_total 1",
            "automata_ci_runner_log_frames_acknowledged_total 3",
            "automata_ci_runner_log_acknowledged_bytes_total 4096",
            "automata_ci_runner_terminal_results_total{stage=\"acknowledged\",conclusion=\"cancelled\"} 1",
        ] {
            assert!(
                exposition.contains(expected),
                "missing semantic sample: {expected}"
            );
        }
        for forbidden in [
            "runner_id=",
            "session_id=",
            "operation_id=",
            "attempt_id=",
            "sequence=",
            "secret-sentinel-value",
        ] {
            assert!(
                !exposition.contains(forbidden),
                "forbidden label: {forbidden}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn durability_and_podman_observers_balance_in_flight_bytes_and_failures() {
        let metrics = RunnerMetrics::new(2, None).expect("runner metrics registry");
        SpoolObserver::observe(
            &metrics,
            SpoolEvent::OperationStarted {
                operation: SpoolOperation::Persist,
            },
        );
        PodmanObserver::observe(
            &metrics,
            PodmanEvent::CommandStarted {
                stage: PodmanCommandStage::Provider(ProviderStage::Validate),
            },
        );
        PodmanObserver::observe(
            &metrics,
            PodmanEvent::DockerRequestStarted {
                route: DockerProxyRoute::Build,
            },
        );
        let in_flight = metrics
            .exporter()
            .encode_openmetrics()
            .expect("in-flight exposition");
        for expected in [
            "automata_ci_runner_spool_operations_in_flight{operation=\"persist\"} 1",
            "automata_ci_runner_podman_commands_in_flight 1",
            "automata_ci_runner_docker_proxy_requests_in_flight{route=\"build\"} 1",
        ] {
            assert!(in_flight.as_str().contains(expected), "missing {expected}");
        }

        SpoolObserver::observe(
            &metrics,
            SpoolEvent::OperationCompleted {
                operation: SpoolOperation::Persist,
                content_kind: Some(ContentKind::JobIr),
                outcome: SpoolOperationOutcome::Error,
                failure: Some(SpoolFailureKind::InvalidInput),
                duration: Duration::from_millis(2),
            },
        );
        SpoolObserver::observe(
            &metrics,
            SpoolEvent::Protection {
                operation: SpoolProtectionOperation::Protect,
                outcome: SpoolProtectionOutcome::Error,
            },
        );
        SpoolObserver::observe(
            &metrics,
            SpoolEvent::CapacityRejected {
                resource: SpoolCapacityResource::ObjectBytes,
            },
        );
        SpoolObserver::observe(
            &metrics,
            SpoolEvent::Reclaimed {
                objects: 2,
                protected_bytes: 4_096,
            },
        );
        PodmanObserver::observe(
            &metrics,
            PodmanEvent::CommandCompleted {
                stage: PodmanCommandStage::Provider(ProviderStage::Validate),
                outcome: PodmanCommandOutcome::OutputTruncated,
                duration: Duration::from_millis(3),
                stdout_bytes: 11,
                stderr_bytes: 7,
            },
        );
        PodmanObserver::observe(
            &metrics,
            PodmanEvent::DockerRequestCompleted {
                route: DockerProxyRoute::Build,
                outcome: DockerProxyOutcome::Rejected,
                duration: Duration::from_millis(4),
                request_bytes: 123,
                response_bytes: 45,
            },
        );
        PodmanObserver::observe(
            &metrics,
            PodmanEvent::DockerRejected {
                reason: DockerProxyRejection::Policy,
            },
        );

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("terminal exposition");
        let exposition = exposition.as_str();
        for expected in [
            "automata_ci_runner_spool_operations_in_flight{operation=\"persist\"} 0",
            "automata_ci_runner_spool_operations_total{operation=\"persist\",outcome=\"error\"} 1",
            "automata_ci_runner_spool_failures_total{kind=\"invalid_input\"} 1",
            "automata_ci_runner_spool_capacity_rejections_total{resource=\"object_bytes\"} 1",
            "automata_ci_runner_spool_reclaimed_objects_total 2",
            "automata_ci_runner_spool_reclaimed_bytes_total 4096",
            "automata_ci_runner_podman_commands_in_flight 0",
            "automata_ci_runner_podman_commands_total{stage=\"provider_validate\"} 1",
            "automata_ci_runner_podman_command_outcomes_total{outcome=\"output_truncated\"} 1",
            "automata_ci_runner_podman_command_output_bytes_total{direction=\"stdout\"} 11",
            "automata_ci_runner_docker_proxy_requests_in_flight{route=\"build\"} 0",
            "automata_ci_runner_docker_proxy_requests_total{route=\"build\",outcome=\"rejected\"} 1",
            "automata_ci_runner_docker_proxy_bytes_total{direction=\"request\"} 123",
            "automata_ci_runner_docker_proxy_rejections_total{reason=\"policy\"} 1",
        ] {
            assert!(exposition.contains(expected), "missing sample: {expected}");
        }
        for forbidden in ["argv=", "image=", "url=", "handle=", "path=", "error="] {
            assert!(
                !exposition.contains(forbidden),
                "private label: {forbidden}"
            );
        }
    }

    #[test]
    fn podman_input_incomplete_uses_one_fixed_secret_free_outcome() {
        let metrics = RunnerMetrics::new(2, None).expect("runner metrics registry");
        let initial = metrics
            .exporter()
            .encode_openmetrics()
            .expect("initial exposition");
        assert!(initial.as_str().contains(
            "automata_ci_runner_podman_command_outcomes_total{outcome=\"input_incomplete\"} 0"
        ));

        PodmanObserver::observe(
            &metrics,
            PodmanEvent::CommandStarted {
                stage: PodmanCommandStage::Endpoint(ExecutionStage::Exec),
            },
        );
        PodmanObserver::observe(
            &metrics,
            PodmanEvent::CommandCompleted {
                stage: PodmanCommandStage::Endpoint(ExecutionStage::Exec),
                outcome: PodmanCommandOutcome::InputIncomplete,
                duration: Duration::from_millis(1),
                stdout_bytes: 0,
                stderr_bytes: 0,
            },
        );

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("input-incomplete exposition");
        let exposition = exposition.as_str();
        for expected in [
            "automata_ci_runner_podman_commands_in_flight 0",
            "automata_ci_runner_podman_commands_total{stage=\"endpoint_exec\"} 1",
            "automata_ci_runner_podman_command_outcomes_total{outcome=\"input_incomplete\"} 1",
        ] {
            assert!(exposition.contains(expected), "missing sample: {expected}");
        }
        for forbidden in [
            "input-incomplete-secret-sentinel",
            "runner_id=",
            "session_id=",
            "operation_id=",
            "attempt_id=",
            "handle=",
        ] {
            assert!(
                !exposition.contains(forbidden),
                "private label: {forbidden}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn sandbox_decorators_record_typed_cancel_truncation_and_complete_bytes() {
        let metrics = RunnerMetrics::new(2, None).expect("runner metrics registry");
        let inner = Arc::new(TestSandboxProvider::new());
        let handle = inner.handle.clone();
        let provider = metrics.instrument_sandbox_provider(inner);
        assert!(matches!(
            provider.inspect(&handle, &NeverCancelled),
            Err(error) if error.kind() == ProviderErrorKind::TimedOut
        ));
        assert_eq!(
            provider
                .service_bindings(&handle, &NeverCancelled)
                .expect("empty bindings"),
            ServiceContainerBindings::empty()
        );
        let endpoint = provider
            .attach(&handle, &NeverCancelled)
            .expect("attach endpoint");
        let command = ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(
                TargetPath::posix("/bin/test").expect("program"),
                vec!["private-argument-sentinel".to_owned()],
            )
            .expect("argv"),
            TargetPath::posix("/workspace").expect("working directory"),
            ExecutionEnvironment::empty(),
            Duration::from_secs(1),
            1_024,
        )
        .expect("command");
        let output = endpoint
            .exec(&command, &NeverCancelled)
            .expect("truncated bounded output");
        assert!(output.was_truncated());
        assert!(matches!(
            endpoint.signal(
                SignalRequest::new(OperationId::new(), ExecutionSignal::Kill),
                &NeverCancelled,
            ),
            Err(error) if error.kind() == ExecutionErrorKind::Cancelled
        ));
        let copy_to = CopyToRequest::new(
            OperationId::new(),
            TargetPath::posix("/workspace/in").expect("copy target"),
            b"private-copy-input".to_vec(),
        )
        .expect("copy-to request");
        endpoint
            .copy_to(&copy_to, &NeverCancelled)
            .expect("copy to");
        let copy_from = CopyFromRequest::new(
            OperationId::new(),
            TargetPath::posix("/workspace/out").expect("copy source"),
            1_024,
        )
        .expect("copy-from request");
        endpoint
            .copy_from(&copy_from, &NeverCancelled)
            .expect("copy from");
        endpoint
            .wait(
                WaitRequest::new(OperationId::new(), Duration::from_secs(1)).expect("wait request"),
                &NeverCancelled,
            )
            .expect("wait");
        assert!(matches!(
            provider.destroy(
                &DestroySandbox::new(
                    OperationId::new(),
                    handle,
                    SandboxGeneration::new(1).expect("generation"),
                    SandboxCustody::ProfileAdmission {
                        runner_id: RunnerId::new(),
                    },
                ),
                &NeverCancelled,
            ),
            Err(error) if error.kind() == ProviderErrorKind::BackendRejected
        ));

        let exposition = metrics
            .exporter()
            .encode_openmetrics()
            .expect("decorator exposition");
        let exposition = exposition.as_str();
        for expected in [
            "automata_ci_runner_sandbox_provider_operations_total{operation=\"inspect\",outcome=\"timed_out\"} 1",
            "automata_ci_runner_sandbox_provider_errors_total{kind=\"timed_out\"} 1",
            "automata_ci_runner_sandbox_provider_operations_total{operation=\"attach\",outcome=\"success\"} 1",
            "automata_ci_runner_sandbox_endpoint_operations_total{operation=\"exec\",outcome=\"success\"} 1",
            "automata_ci_runner_sandbox_endpoint_operations_total{operation=\"signal\",outcome=\"cancelled\"} 1",
            "automata_ci_runner_sandbox_endpoint_errors_total{kind=\"cancelled\"} 1",
            "automata_ci_runner_sandbox_endpoint_terminations_total{kind=\"exited\"} 1",
            "automata_ci_runner_sandbox_endpoint_output_truncations_total 1",
            "automata_ci_runner_sandbox_endpoint_bytes_total{direction=\"copy_to\"} 18",
            "automata_ci_runner_sandbox_endpoint_bytes_total{direction=\"copy_from\"} 21",
        ] {
            assert!(exposition.contains(expected), "missing sample: {expected}");
        }
        for forbidden in [
            "private-handle-sentinel",
            "private-output-sentinel",
            "private-copy-sentinel",
            "private-argument-sentinel",
            "operation_id=",
            "error=",
        ] {
            assert!(
                !exposition.contains(forbidden),
                "private value: {forbidden}"
            );
        }
    }

    #[test]
    fn concurrent_snapshot_updates_and_scrapes_remain_coherent_and_bounded() {
        let metrics = Arc::new(RunnerMetrics::new(8, None).expect("runner metrics registry"));
        let mut workers = Vec::new();
        for worker in 0_u64..4 {
            let metrics = Arc::clone(&metrics);
            workers.push(thread::spawn(move || {
                for revision in 0_u64..100 {
                    let mut counts = SnapshotCounts {
                        journal_revision: worker * 100 + revision,
                        ..SnapshotCounts::default()
                    };
                    if revision.is_multiple_of(2) {
                        counts.journal_slots = 12;
                        counts.slots[SlotState::Running.index()] = 12;
                    } else {
                        counts.slots[SlotState::Idle.index()] = 8;
                    }
                    metrics.snapshot.apply_journal(counts);
                    let exposition = metrics
                        .exporter()
                        .encode_openmetrics()
                        .expect("concurrent OpenMetrics exposition");
                    assert!(exposition.len() < 2 * 1024 * 1024);
                    assert!(exposition.as_str().ends_with("# EOF\n"));
                    let exposition = exposition.as_str();
                    let configured =
                        scalar_sample(exposition, "automata_ci_runner_slots_configured");
                    let journal = scalar_sample(exposition, "automata_ci_runner_journal_slots");
                    let overflow =
                        scalar_sample(exposition, "automata_ci_runner_slots_over_capacity");
                    let conserved =
                        scalar_sample(exposition, "automata_ci_runner_slot_snapshot_conserved");
                    let state_total = exposition
                        .lines()
                        .filter(|line| line.starts_with("automata_ci_runner_slots{"))
                        .map(sample_value)
                        .sum::<u64>();
                    assert_eq!(state_total, configured.max(journal));
                    assert_eq!(overflow, journal.saturating_sub(configured));
                    assert_eq!(conserved, 1);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("metrics worker must not panic");
        }
    }

    fn scalar_sample(exposition: &str, name: &str) -> u64 {
        exposition
            .lines()
            .find(|line| line.starts_with(name) && line.as_bytes().get(name.len()) == Some(&b' '))
            .map_or_else(|| panic!("missing scalar sample: {name}"), sample_value)
    }

    fn sample_value(line: &str) -> u64 {
        line.rsplit_once(' ')
            .unwrap_or_else(|| panic!("sample has no value: {line}"))
            .1
            .parse()
            .unwrap_or_else(|_| panic!("sample is not an integer: {line}"))
    }
}
