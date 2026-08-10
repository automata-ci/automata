use std::{
    fmt,
    future::Future,
    sync::{Arc, Mutex, PoisonError, atomic::AtomicU64},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use automata_ci_control_plane::{
    AuthorizedRunnerRouting, CandidateCapacity, EffectiveRunner, RoutingRequirements,
    RunnableCandidate, RunnerEvidence, RunnerSlot, SessionGuard, classify_candidate_capacity,
    intersect_runner_capabilities,
};
use automata_ci_core::{JobLifecycle, RunnerGroup, RunnerLabel, UnixMillis};
use automata_ci_metrics::{
    Counter, Family, Gauge, Histogram, Registry, Unit, classic_and_native_histogram,
};
use automata_ci_store::{
    ArtifactReservationKind, ArtifactState, BuiltinSecretCleanupStatus,
    ControlPlaneStateRepository, ControlPlaneStateSnapshot, ControlPlaneStateSnapshotRequest,
    DatabasePoolSnapshot, JobAttemptCounts, LEASE_NEAR_EXPIRY_WINDOW, LeaseState,
    LogicalActivationState, LogicalJobState, RunnerDesiredState, RunnerObservedState,
    RunnerSessionState, WorkflowPlanV2RunState, WorkflowRunCounts, WorkflowRunStatus,
};
use prometheus_client::{
    collector::Collector,
    encoding::{
        DescriptorEncoder, EncodeLabelSet, EncodeLabelValue, EncodeMetric, LabelValueEncoder,
    },
    metrics::{MetricType, gauge::ConstGauge},
};

/// Fixed interval between durable-state refresh attempts.
pub(crate) const CONTROL_PLANE_STATE_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(15);

const STATE_DURATION_BUCKETS_SECONDS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

type FloatGauge = Gauge<f64, AtomicU64>;
type UnsignedGauge = Gauge<u64, AtomicU64>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct StatusLabels {
    status: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct LifecycleLabels {
    lifecycle: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RunnerStateLabels {
    observed_state: &'static str,
    desired_state: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct StateLabels {
    state: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct KindLabels {
    kind: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ReasonLabels {
    reason: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct SamplerOutcomeLabels {
    outcome: SamplerOutcome,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SamplerOutcome {
    Success,
    Error,
    Cancelled,
}

impl SamplerOutcome {
    const ALL: [Self; 3] = [Self::Success, Self::Error, Self::Cancelled];
}

impl EncodeLabelValue for SamplerOutcome {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        use fmt::Write as _;

        encoder.write_str(match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PublishedControlPlaneState {
    durable: ControlPlaneStateSnapshot,
    capacity: CompatibleCapacitySnapshot,
    pool: DatabasePoolSnapshot,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CompatibleCapacitySnapshot {
    blocked: [u64; 2],
    oldest_at: [Option<UnixMillis>; 2],
}

/// Custom collector that reads exactly one immutable last-good snapshot per encode.
#[derive(Debug, Default)]
struct ControlPlaneStateCollector {
    published: Mutex<PublishedControlPlaneState>,
}

impl ControlPlaneStateCollector {
    fn publish(
        &self,
        durable: ControlPlaneStateSnapshot,
        capacity: CompatibleCapacitySnapshot,
        pool: DatabasePoolSnapshot,
    ) {
        *self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = PublishedControlPlaneState {
            durable,
            capacity,
            pool,
        };
    }

    fn snapshot(&self) -> PublishedControlPlaneState {
        self.published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Collector for ControlPlaneStateCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        let published = self.snapshot();
        encode_workflow_runs(&mut encoder, published.durable.workflow_runs())?;
        encode_logical_orchestration(&mut encoder, &published.durable)?;
        encode_job_attempts(&mut encoder, published.durable.job_attempts())?;
        encode_runners(&mut encoder, published.durable.runners())?;
        encode_runner_sessions(&mut encoder, published.durable.runner_sessions())?;
        encode_queue(&mut encoder, &published.durable)?;
        encode_compatible_capacity(&mut encoder, published.capacity)?;
        encode_leases(&mut encoder, published.durable.leases())?;
        encode_commands(&mut encoder, &published.durable)?;
        encode_cancellation_intents(&mut encoder, &published.durable)?;
        encode_builtin_secret_cleanup(&mut encoder, &published.durable)?;
        encode_artifacts(&mut encoder, &published.durable)?;
        encode_artifact_reservations(&mut encoder, &published.durable)?;
        encode_pool(&mut encoder, published.pool)
    }
}

#[derive(Clone)]
pub(crate) struct ControlPlaneStateMetrics {
    collector: Arc<ControlPlaneStateCollector>,
    runs: Family<SamplerOutcomeLabels, Counter>,
    duration: Family<SamplerOutcomeLabels, Histogram>,
    healthy: Gauge,
    last_success_timestamp: FloatGauge,
}

impl fmt::Debug for ControlPlaneStateMetrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlaneStateMetrics")
            .finish_non_exhaustive()
    }
}

impl ControlPlaneStateMetrics {
    pub(crate) fn register(registry: &mut Registry) -> Self {
        let collector = Arc::new(ControlPlaneStateCollector::default());
        registry.register_collector(Box::new(Arc::clone(&collector)));

        let runs = Family::<SamplerOutcomeLabels, Counter>::default();
        registry.register(
            "control_plane_state_sampler_runs",
            "Durable control-plane state snapshot attempts by bounded outcome.",
            runs.clone(),
        );
        let duration = Family::<SamplerOutcomeLabels, Histogram>::new_with_constructor(|| {
            classic_and_native_histogram(STATE_DURATION_BUCKETS_SECONDS)
        });
        registry.register_with_unit(
            "control_plane_state_sampler_duration",
            "Durable control-plane state snapshot duration by bounded outcome.",
            Unit::Seconds,
            duration.clone(),
        );
        let healthy = Gauge::default();
        registry.register(
            "control_plane_state_sampler_healthy",
            "Whether the most recent durable-state snapshot attempt succeeded.",
            healthy.clone(),
        );
        let last_success_timestamp = FloatGauge::default();
        registry.register_with_unit(
            "control_plane_state_sampler_last_success_timestamp",
            "Unix timestamp of the last successful durable-state snapshot.",
            Unit::Seconds,
            last_success_timestamp.clone(),
        );
        for outcome in SamplerOutcome::ALL {
            let labels = SamplerOutcomeLabels { outcome };
            let _ = runs.get_or_create(&labels);
            let _ = duration.get_or_create(&labels);
        }
        Self {
            collector,
            runs,
            duration,
            healthy,
            last_success_timestamp,
        }
    }

    pub(crate) fn sampler(
        &self,
        source: Arc<dyn ControlPlaneStateRepository>,
    ) -> ControlPlaneStateSampler {
        ControlPlaneStateSampler {
            source,
            metrics: self.clone(),
        }
    }

    fn observe(
        &self,
        outcome: SamplerOutcome,
        duration: Duration,
        replacement: Option<(
            ControlPlaneStateSnapshot,
            CompatibleCapacitySnapshot,
            DatabasePoolSnapshot,
        )>,
        completed_at_seconds: f64,
    ) {
        let labels = SamplerOutcomeLabels { outcome };
        self.runs.get_or_create(&labels).inc();
        self.duration
            .get_or_create(&labels)
            .observe(duration.as_secs_f64());
        if let Some((durable, capacity, pool)) = replacement {
            self.collector.publish(durable, capacity, pool);
            self.healthy.set(1);
            self.last_success_timestamp.set(completed_at_seconds);
        } else {
            self.healthy.set(0);
        }
    }
}

struct StateRefreshObservation<'a> {
    metrics: &'a ControlPlaneStateMetrics,
    started: Instant,
    finished: bool,
}

impl<'a> StateRefreshObservation<'a> {
    fn start(metrics: &'a ControlPlaneStateMetrics) -> Self {
        Self {
            metrics,
            started: Instant::now(),
            finished: false,
        }
    }

    fn finish(
        mut self,
        outcome: SamplerOutcome,
        replacement: Option<(
            ControlPlaneStateSnapshot,
            CompatibleCapacitySnapshot,
            DatabasePoolSnapshot,
        )>,
        completed_at_seconds: f64,
    ) {
        self.metrics.observe(
            outcome,
            self.started.elapsed(),
            replacement,
            completed_at_seconds,
        );
        self.finished = true;
    }
}

impl Drop for StateRefreshObservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics
                .observe(SamplerOutcome::Cancelled, self.started.elapsed(), None, 0.0);
        }
    }
}

/// Off-scrape durable-state sampler supervised beside the metrics listener.
#[derive(Clone)]
pub(crate) struct ControlPlaneStateSampler {
    source: Arc<dyn ControlPlaneStateRepository>,
    metrics: ControlPlaneStateMetrics,
}

impl fmt::Debug for ControlPlaneStateSampler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlaneStateSampler")
            .finish_non_exhaustive()
    }
}

impl ControlPlaneStateSampler {
    /// Attempts an immediate refresh, then every 15 seconds, until shutdown.
    pub(crate) async fn run_until_cancelled<F>(self, shutdown: F)
    where
        F: Future<Output = ()> + Send,
    {
        self.run_until_cancelled_with_interval(shutdown, CONTROL_PLANE_STATE_SNAPSHOT_INTERVAL)
            .await;
    }

    async fn run_until_cancelled_with_interval<F>(self, shutdown: F, interval: Duration)
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        tokio::select! {
            biased;
            () = &mut shutdown => return,
            () = self.refresh_now() => {}
        }

        let first_refresh = tokio::time::Instant::now() + interval;
        let mut ticker = tokio::time::interval_at(first_refresh, interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return,
                _ = ticker.tick() => self.refresh_now().await,
            }
        }
    }

    async fn refresh_now(&self) {
        let observation = StateRefreshObservation::start(&self.metrics);
        if let Some(((durable, capacity, pool), completed_at_seconds)) = self
            .load_snapshot()
            .await
            .zip(unix_seconds(SystemTime::now()))
        {
            observation.finish(
                SamplerOutcome::Success,
                Some((durable, capacity, pool)),
                completed_at_seconds,
            );
        } else {
            observation.finish(SamplerOutcome::Error, None, 0.0);
        }
    }

    async fn load_snapshot(
        &self,
    ) -> Option<(
        ControlPlaneStateSnapshot,
        CompatibleCapacitySnapshot,
        DatabasePoolSnapshot,
    )> {
        let observed_at = unix_millis(SystemTime::now())?;
        let request =
            ControlPlaneStateSnapshotRequest::new(observed_at, LEASE_NEAR_EXPIRY_WINDOW).ok()?;
        let durable = self
            .source
            .control_plane_state_snapshot(request)
            .await
            .ok()?;
        let capacity = compatible_capacity_snapshot(&durable, observed_at)?;
        let pool = self.source.database_pool_snapshot().ok()?;
        Some((durable, capacity, pool))
    }
}

fn compatible_capacity_snapshot(
    snapshot: &ControlPlaneStateSnapshot,
    observed_at: UnixMillis,
) -> Option<CompatibleCapacitySnapshot> {
    let mut runners_by_tenant = std::collections::BTreeMap::<&str, Vec<EffectiveRunner>>::new();
    for runner in snapshot.capacity().runners() {
        runners_by_tenant
            .entry(runner.tenant_id())
            .or_default()
            .push(effective_capacity_runner(runner, observed_at)?);
    }

    let mut result = CompatibleCapacitySnapshot::default();
    for durable in snapshot.capacity().candidates() {
        let routing = RoutingRequirements::new(durable.requirements().clone()).ok()?;
        let candidate = RunnableCandidate::new(
            durable.attempt_id(),
            durable.job_id(),
            durable.queued_at(),
            routing,
        );
        let runners = runners_by_tenant
            .get(durable.tenant_id())
            .map_or(&[][..], Vec::as_slice);
        let reason = match classify_candidate_capacity(&candidate, runners) {
            CandidateCapacity::Available => continue,
            CandidateCapacity::NoCompatibleRunner => 0,
            CandidateCapacity::CompatibleRunnersBusy => 1,
        };
        result.blocked[reason] = result.blocked[reason].checked_add(1)?;
        result.oldest_at[reason] = Some(
            result.oldest_at[reason]
                .map_or(durable.queued_at(), |prior| prior.min(durable.queued_at())),
        );
    }
    Some(result)
}

fn effective_capacity_runner(
    durable: &automata_ci_store::ControlPlaneCapacityRunner,
    observed_at: UnixMillis,
) -> Option<EffectiveRunner> {
    let machine_capabilities = intersect_runner_capabilities(
        durable.registered_capabilities(),
        durable.observed_capabilities(),
    )
    .ok()?;
    let session = SessionGuard::new(
        durable.session().runner_id(),
        durable.session().session_id(),
    );
    let evidence = RunnerEvidence::new(
        session,
        durable.observed_capabilities().clone(),
        observed_at,
    )
    .ok()?;
    let labels = durable
        .labels()
        .iter()
        .map(|label| RunnerLabel::new(label.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let groups = durable
        .group_name()
        .map(RunnerGroup::new)
        .transpose()
        .ok()?;
    let routing = AuthorizedRunnerRouting::new(labels, groups);
    let maximum = durable
        .slots()
        .get()
        .min(machine_capabilities.max_parallel_jobs());
    let available = (1..=maximum).find_map(|ordinal| {
        let stable = automata_ci_store::StableRunnerSlot::new(ordinal).ok()?;
        (!durable.occupied_slots().contains(&stable))
            .then(|| RunnerSlot::new(durable.session().runner_id(), ordinal).ok())?
    });
    EffectiveRunner::authorize(&evidence, routing, machine_capabilities, available).ok()
}

fn encode_workflow_runs(
    encoder: &mut DescriptorEncoder<'_>,
    counts: WorkflowRunCounts,
) -> Result<(), fmt::Error> {
    let family = Family::<StatusLabels, UnsignedGauge>::default();
    for status in WorkflowRunCounts::ALL {
        family
            .get_or_create(&StatusLabels {
                status: workflow_status(status),
            })
            .set(counts.get(status));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_workflow_runs",
        "Durable workflow runs by closed aggregate status.",
        None,
        MetricType::Gauge,
    )?;
    family.encode(metric)
}

fn encode_logical_orchestration(
    encoder: &mut DescriptorEncoder<'_>,
    snapshot: &ControlPlaneStateSnapshot,
) -> Result<(), fmt::Error> {
    let runs = Family::<StateLabels, UnsignedGauge>::default();
    let run_counts = snapshot.workflow_plan_v2_runs();
    for state in WorkflowPlanV2RunState::ALL {
        runs.get_or_create(&StateLabels {
            state: workflow_plan_v2_run_state(state),
        })
        .set(run_counts.get(state));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_workflow_plan_v2_runs",
        "Durable current WorkflowPlan-v2 orchestration markers by closed state.",
        None,
        MetricType::Gauge,
    )?;
    runs.encode(metric)?;

    let jobs = Family::<StateLabels, UnsignedGauge>::default();
    let job_counts = snapshot.logical_jobs();
    for state in LogicalJobState::ALL {
        jobs.get_or_create(&StateLabels {
            state: logical_job_state(state),
        })
        .set(job_counts.get(state));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_logical_jobs",
        "Durable current WorkflowPlan-v2 logical jobs by closed state.",
        None,
        MetricType::Gauge,
    )?;
    jobs.encode(metric)?;

    let activations = Family::<StateLabels, UnsignedGauge>::default();
    let oldest = Family::<StateLabels, FloatGauge>::default();
    let activation_counts = snapshot.logical_activations();
    for state in LogicalActivationState::ALL {
        let labels = StateLabels {
            state: logical_activation_state(state),
        };
        activations
            .get_or_create(&labels)
            .set(activation_counts.get(state));
        oldest
            .get_or_create(&labels)
            .set(timestamp_seconds(activation_counts.oldest_at(state)));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_logical_activations",
        "Current logical activation backlog and claims by closed observation state.",
        None,
        MetricType::Gauge,
    )?;
    activations.encode(metric)?;
    let unit = Unit::Seconds;
    let metric = encoder.encode_descriptor(
        "control_plane_logical_activation_oldest_timestamp",
        "Unix timestamp of the oldest logical activation backlog or claim by state, or zero when empty.",
        Some(&unit),
        MetricType::Gauge,
    )?;
    oldest.encode(metric)?;

    encode_unsigned_gauge(
        encoder,
        "control_plane_logical_activation_publications",
        "Durable current logical activation publications.",
        snapshot.activation_publications(),
    )?;
    encode_unsigned_gauge(
        encoder,
        "control_plane_logical_materialized_instances",
        "Durable current logical instances materialized by activation.",
        snapshot.materialized_instances(),
    )
}

fn encode_job_attempts(
    encoder: &mut DescriptorEncoder<'_>,
    counts: JobAttemptCounts,
) -> Result<(), fmt::Error> {
    let family = Family::<LifecycleLabels, UnsignedGauge>::default();
    for lifecycle in JobAttemptCounts::ALL {
        family
            .get_or_create(&LifecycleLabels {
                lifecycle: job_lifecycle(lifecycle),
            })
            .set(counts.get(lifecycle));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_job_attempts",
        "Durable job attempts by closed lifecycle.",
        None,
        MetricType::Gauge,
    )?;
    family.encode(metric)
}

fn encode_runners(
    encoder: &mut DescriptorEncoder<'_>,
    counts: automata_ci_store::RunnerCounts,
) -> Result<(), fmt::Error> {
    let family = Family::<RunnerStateLabels, UnsignedGauge>::default();
    for observed in RunnerObservedState::ALL {
        for desired in RunnerDesiredState::ALL {
            family
                .get_or_create(&RunnerStateLabels {
                    observed_state: runner_observed_state(observed),
                    desired_state: runner_desired_state(desired),
                })
                .set(counts.get(observed, desired));
        }
    }
    let metric = encoder.encode_descriptor(
        "control_plane_runners",
        "Registered runners by closed durable observed and desired state.",
        None,
        MetricType::Gauge,
    )?;
    family.encode(metric)
}

fn encode_runner_sessions(
    encoder: &mut DescriptorEncoder<'_>,
    counts: automata_ci_store::RunnerSessionCounts,
) -> Result<(), fmt::Error> {
    let family = Family::<StateLabels, UnsignedGauge>::default();
    for state in RunnerSessionState::ALL {
        family
            .get_or_create(&StateLabels {
                state: runner_session_state(state),
            })
            .set(counts.get(state));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_runner_sessions",
        "Durable runner sessions by closed connectivity state.",
        None,
        MetricType::Gauge,
    )?;
    family.encode(metric)
}

fn encode_queue(
    encoder: &mut DescriptorEncoder<'_>,
    snapshot: &ControlPlaneStateSnapshot,
) -> Result<(), fmt::Error> {
    let family = Family::<StateLabels, UnsignedGauge>::default();
    for (state, depth) in [
        ("queued", snapshot.queue_depth()),
        ("eligible", snapshot.eligible_queue_depth()),
    ] {
        family.get_or_create(&StateLabels { state }).set(depth);
    }
    let metric = encoder.encode_descriptor(
        "control_plane_queue_jobs",
        "Durable scheduler queue depth by closed queue state.",
        None,
        MetricType::Gauge,
    )?;
    family.encode(metric)?;

    let timestamps = Family::<StateLabels, FloatGauge>::default();
    for (state, oldest_at) in [
        ("queued", snapshot.queue_oldest_at()),
        ("eligible", snapshot.eligible_queue_oldest_at()),
    ] {
        timestamps
            .get_or_create(&StateLabels { state })
            .set(timestamp_seconds(oldest_at));
    }
    let unit = Unit::Seconds;
    let metric = encoder.encode_descriptor(
        "control_plane_queue_oldest_timestamp",
        "Unix timestamp of the oldest durable queued attempt, or zero when empty.",
        Some(&unit),
        MetricType::Gauge,
    )?;
    timestamps.encode(metric)
}

fn encode_compatible_capacity(
    encoder: &mut DescriptorEncoder<'_>,
    snapshot: CompatibleCapacitySnapshot,
) -> Result<(), fmt::Error> {
    let blocked = Family::<ReasonLabels, UnsignedGauge>::default();
    let oldest = Family::<ReasonLabels, FloatGauge>::default();
    for (index, reason) in ["no_compatible_runner", "compatible_runners_busy"]
        .into_iter()
        .enumerate()
    {
        let labels = ReasonLabels { reason };
        blocked.get_or_create(&labels).set(snapshot.blocked[index]);
        oldest
            .get_or_create(&labels)
            .set(timestamp_seconds(snapshot.oldest_at[index]));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_eligible_queue_blocked_jobs",
        "Exact eligible queued attempts blocked by bounded compatible-capacity reason.",
        None,
        MetricType::Gauge,
    )?;
    blocked.encode(metric)?;
    let unit = Unit::Seconds;
    let metric = encoder.encode_descriptor(
        "control_plane_eligible_queue_blocked_oldest_timestamp",
        "Unix timestamp of the oldest exact eligible attempt blocked by compatible-capacity reason, or zero when empty.",
        Some(&unit),
        MetricType::Gauge,
    )?;
    oldest.encode(metric)
}

fn encode_leases(
    encoder: &mut DescriptorEncoder<'_>,
    counts: automata_ci_store::LeaseCounts,
) -> Result<(), fmt::Error> {
    let family = Family::<StateLabels, UnsignedGauge>::default();
    for state in LeaseState::ALL {
        family
            .get_or_create(&StateLabels {
                state: lease_state(state),
            })
            .set(counts.get(state));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_leases",
        "Durable active-lifecycle leases by expiry band at snapshot time.",
        None,
        MetricType::Gauge,
    )?;
    family.encode(metric)
}

fn encode_commands(
    encoder: &mut DescriptorEncoder<'_>,
    snapshot: &ControlPlaneStateSnapshot,
) -> Result<(), fmt::Error> {
    encode_unsigned_gauge(
        encoder,
        "control_plane_commands_pending",
        "Durable runner commands above their session's acknowledged cursor.",
        snapshot.pending_commands(),
    )?;
    encode_timestamp_gauge(
        encoder,
        "control_plane_commands_oldest_timestamp",
        "Unix timestamp of the oldest pending durable runner command, or zero when empty.",
        snapshot.pending_commands_oldest_at(),
    )
}

fn encode_cancellation_intents(
    encoder: &mut DescriptorEncoder<'_>,
    snapshot: &ControlPlaneStateSnapshot,
) -> Result<(), fmt::Error> {
    encode_unsigned_gauge(
        encoder,
        "control_plane_cancellation_intents_pending",
        "Durable attempt-cancellation intents not yet acknowledged by a runner.",
        snapshot.pending_cancellation_intents(),
    )?;
    encode_timestamp_gauge(
        encoder,
        "control_plane_cancellation_intents_oldest_timestamp",
        "Unix timestamp of the oldest unacknowledged cancellation intent, or zero when empty.",
        snapshot.pending_cancellation_intents_oldest_at(),
    )
}

fn encode_builtin_secret_cleanup(
    encoder: &mut DescriptorEncoder<'_>,
    snapshot: &ControlPlaneStateSnapshot,
) -> Result<(), fmt::Error> {
    let cleanup = snapshot.builtin_secret_cleanup();
    let operations = Family::<StatusLabels, UnsignedGauge>::default();
    let oldest = Family::<StatusLabels, FloatGauge>::default();
    for status in BuiltinSecretCleanupStatus::ALL {
        let labels = StatusLabels {
            status: builtin_secret_cleanup_status(status),
        };
        operations.get_or_create(&labels).set(cleanup.get(status));
        oldest
            .get_or_create(&labels)
            .set(timestamp_seconds(cleanup.oldest_created_at(status)));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_builtin_secret_cleanup_operations",
        "Durable built-in secret-version cleanup operations by closed status.",
        None,
        MetricType::Gauge,
    )?;
    operations.encode(metric)?;
    let unit = Unit::Seconds;
    let metric = encoder.encode_descriptor(
        "control_plane_builtin_secret_cleanup_oldest_created_timestamp",
        "Unix timestamp of the oldest durable built-in secret-version cleanup operation by closed status, or zero when empty.",
        Some(&unit),
        MetricType::Gauge,
    )?;
    oldest.encode(metric)
}

fn encode_artifacts(
    encoder: &mut DescriptorEncoder<'_>,
    snapshot: &ControlPlaneStateSnapshot,
) -> Result<(), fmt::Error> {
    let family = Family::<StateLabels, UnsignedGauge>::default();
    let counts = snapshot.artifacts();
    for state in ArtifactState::ALL {
        family
            .get_or_create(&StateLabels {
                state: artifact_state(state),
            })
            .set(counts.get(state));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_artifacts",
        "Durable workflow artifacts by closed publication state.",
        None,
        MetricType::Gauge,
    )?;
    family.encode(metric)
}

fn encode_artifact_reservations(
    encoder: &mut DescriptorEncoder<'_>,
    snapshot: &ControlPlaneStateSnapshot,
) -> Result<(), fmt::Error> {
    let reservations = snapshot.artifact_reservations();
    let counts = Family::<KindLabels, UnsignedGauge>::default();
    let timestamps = Family::<KindLabels, FloatGauge>::default();
    for kind in ArtifactReservationKind::ALL {
        let labels = KindLabels {
            kind: artifact_reservation_kind(kind),
        };
        counts.get_or_create(&labels).set(reservations.get(kind));
        timestamps
            .get_or_create(&labels)
            .set(timestamp_seconds(reservations.oldest_at(kind)));
    }
    let metric = encoder.encode_descriptor(
        "control_plane_artifact_reservations",
        "Outstanding immutable artifact reservations by closed kind.",
        None,
        MetricType::Gauge,
    )?;
    counts.encode(metric)?;

    let unit = Unit::Seconds;
    let metric = encoder.encode_descriptor(
        "control_plane_artifact_reservation_oldest_timestamp",
        "Unix timestamp of the oldest outstanding artifact reservation by kind, or zero when empty.",
        Some(&unit),
        MetricType::Gauge,
    )?;
    timestamps.encode(metric)
}

fn encode_pool(
    encoder: &mut DescriptorEncoder<'_>,
    pool: DatabasePoolSnapshot,
) -> Result<(), fmt::Error> {
    let family = Family::<StateLabels, UnsignedGauge>::default();
    for (state, count) in [
        ("open", u64::from(pool.open())),
        ("idle", u64::from(pool.idle())),
        ("in_use", u64::from(pool.in_use())),
    ] {
        family.get_or_create(&StateLabels { state }).set(count);
    }
    let metric = encoder.encode_descriptor(
        "postgres_pool_connections",
        "Cached SQLx PostgreSQL pool connections by closed occupancy state.",
        None,
        MetricType::Gauge,
    )?;
    family.encode(metric)?;
    encode_unsigned_gauge(
        encoder,
        "postgres_pool_max_connections",
        "Configured maximum SQLx PostgreSQL pool connections.",
        u64::from(pool.maximum()),
    )
}

fn encode_unsigned_gauge(
    encoder: &mut DescriptorEncoder<'_>,
    name: &'static str,
    help: &'static str,
    value: u64,
) -> Result<(), fmt::Error> {
    let gauge = ConstGauge::new(value);
    let metric = encoder.encode_descriptor(name, help, None, MetricType::Gauge)?;
    gauge.encode(metric)
}

fn encode_timestamp_gauge(
    encoder: &mut DescriptorEncoder<'_>,
    name: &'static str,
    help: &'static str,
    value: Option<UnixMillis>,
) -> Result<(), fmt::Error> {
    let gauge = ConstGauge::new(timestamp_seconds(value));
    let unit = Unit::Seconds;
    let metric = encoder.encode_descriptor(name, help, Some(&unit), MetricType::Gauge)?;
    gauge.encode(metric)
}

const fn workflow_status(status: WorkflowRunStatus) -> &'static str {
    match status {
        WorkflowRunStatus::Queued => "queued",
        WorkflowRunStatus::InProgress => "in_progress",
        WorkflowRunStatus::Completed => "completed",
        WorkflowRunStatus::Cancelled => "cancelled",
    }
}

const fn workflow_plan_v2_run_state(state: WorkflowPlanV2RunState) -> &'static str {
    match state {
        WorkflowPlanV2RunState::Pending => "pending",
        WorkflowPlanV2RunState::Active => "active",
        WorkflowPlanV2RunState::Completed => "completed",
        WorkflowPlanV2RunState::Cancelled => "cancelled",
        WorkflowPlanV2RunState::Failed => "failed",
    }
}

const fn logical_job_state(state: LogicalJobState) -> &'static str {
    match state {
        LogicalJobState::Pending => "pending",
        LogicalJobState::Activating => "activating",
        LogicalJobState::Activated => "activated",
        LogicalJobState::Completed => "completed",
        LogicalJobState::Skipped => "skipped",
        LogicalJobState::Cancelled => "cancelled",
        LogicalJobState::Failed => "failed",
    }
}

const fn logical_activation_state(state: LogicalActivationState) -> &'static str {
    match state {
        LogicalActivationState::Pending => "pending",
        LogicalActivationState::Activating => "activating",
        LogicalActivationState::Expired => "expired",
    }
}

const fn job_lifecycle(lifecycle: JobLifecycle) -> &'static str {
    match lifecycle {
        JobLifecycle::Queued => "queued",
        JobLifecycle::Leased => "leased",
        JobLifecycle::Preparing => "preparing",
        JobLifecycle::Running => "running",
        JobLifecycle::Cancelling => "cancelling",
        JobLifecycle::Finalizing => "finalizing",
        JobLifecycle::Succeeded => "succeeded",
        JobLifecycle::Failed => "failed",
        JobLifecycle::Cancelled => "cancelled",
        JobLifecycle::TimedOut => "timed_out",
        JobLifecycle::Skipped => "skipped",
        JobLifecycle::Lost => "lost",
    }
}

const fn runner_observed_state(state: RunnerObservedState) -> &'static str {
    match state {
        RunnerObservedState::Offline => "offline",
        RunnerObservedState::Online => "online",
    }
}

const fn runner_desired_state(state: RunnerDesiredState) -> &'static str {
    match state {
        RunnerDesiredState::Active => "active",
        RunnerDesiredState::Draining => "draining",
        RunnerDesiredState::Disabled => "disabled",
    }
}

const fn runner_session_state(state: RunnerSessionState) -> &'static str {
    match state {
        RunnerSessionState::Live => "live",
        RunnerSessionState::Disconnected => "disconnected",
    }
}

const fn lease_state(state: LeaseState) -> &'static str {
    match state {
        LeaseState::Active => "active",
        LeaseState::NearExpiry => "near_expiry",
        LeaseState::Expired => "expired",
    }
}

const fn artifact_state(state: ArtifactState) -> &'static str {
    match state {
        ArtifactState::PendingUpload => "pending_upload",
        ArtifactState::PublicationReserved => "publication_reserved",
        ArtifactState::Finalized => "finalized",
    }
}

const fn artifact_reservation_kind(kind: ArtifactReservationKind) -> &'static str {
    match kind {
        ArtifactReservationKind::Block => "block",
        ArtifactReservationKind::Manifest => "manifest",
    }
}

const fn builtin_secret_cleanup_status(status: BuiltinSecretCleanupStatus) -> &'static str {
    match status {
        BuiltinSecretCleanupStatus::Pending => "pending",
        BuiltinSecretCleanupStatus::InProgress => "in_progress",
        BuiltinSecretCleanupStatus::DeadLetter => "dead_letter",
    }
}

#[allow(clippy::cast_precision_loss)] // OpenMetrics timestamps are represented as IEEE-754 seconds.
fn timestamp_seconds(timestamp: Option<UnixMillis>) -> f64 {
    timestamp.map_or(0.0, |value| value.get() as f64 / 1_000.0)
}

fn unix_millis(timestamp: SystemTime) -> Option<UnixMillis> {
    let millis = timestamp.duration_since(UNIX_EPOCH).ok()?.as_millis();
    i64::try_from(millis).ok().map(UnixMillis::new)
}

fn unix_seconds(timestamp: SystemTime) -> Option<f64> {
    timestamp
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .ok()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, VecDeque},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use automata_ci_core::{
        Architecture, AttemptId, JobId, OperatingSystem, RunnerCapabilities, RunnerId,
        RunnerPlatform, RunnerRequirements, RunnerSessionId,
    };
    use automata_ci_metrics::{BuildInfo, ExporterLimits, Metrics, MetricsBuilder, ProcessRole};
    use automata_ci_store::{
        ArtifactCounts, ArtifactReservations, BuiltinSecretCleanupCounts,
        ControlPlaneCapacityCandidate, ControlPlaneCapacityRunner, ControlPlaneStateValueError,
        JobAttemptCounts, LeaseCounts, LogicalActivationCounts, LogicalJobCounts, RoutingLabel,
        RunnerCounts, RunnerGeneration, RunnerSessionCounts, RunnerSessionFence, RunnerSlotCount,
        SessionEpoch, StableRunnerSlot, WorkflowPlanV2RunCounts,
    };
    use tokio::sync::Notify;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[derive(Debug)]
    struct FakeRepository {
        snapshots: Mutex<VecDeque<ControlPlaneStateSnapshot>>,
        fallback: Mutex<ControlPlaneStateSnapshot>,
        fail: AtomicBool,
        state_calls: AtomicUsize,
        pool_calls: AtomicUsize,
        pool: DatabasePoolSnapshot,
    }

    impl FakeRepository {
        fn new(snapshot: ControlPlaneStateSnapshot) -> Self {
            Self {
                snapshots: Mutex::new(VecDeque::new()),
                fallback: Mutex::new(snapshot),
                fail: AtomicBool::new(false),
                state_calls: AtomicUsize::new(0),
                pool_calls: AtomicUsize::new(0),
                pool: DatabasePoolSnapshot::new(20, 12, 7).expect("valid fake pool"),
            }
        }

        fn enqueue(&self, snapshot: ControlPlaneStateSnapshot) {
            self.snapshots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(snapshot);
        }
    }

    #[async_trait]
    impl ControlPlaneStateRepository for FakeRepository {
        async fn control_plane_state_snapshot(
            &self,
            _request: ControlPlaneStateSnapshotRequest,
        ) -> Result<ControlPlaneStateSnapshot, automata_ci_store::StoreError> {
            self.state_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Relaxed) {
                return Err(automata_ci_store::StoreError::corrupt_data(
                    "synthetic snapshot failure",
                ));
            }
            if let Some(snapshot) = self
                .snapshots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
            {
                *self.fallback.lock().unwrap_or_else(PoisonError::into_inner) = snapshot.clone();
                return Ok(snapshot);
            }
            Ok(self
                .fallback
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone())
        }

        fn database_pool_snapshot(
            &self,
        ) -> Result<DatabasePoolSnapshot, automata_ci_store::StoreError> {
            self.pool_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.pool)
        }
    }

    #[derive(Debug, Default)]
    struct BlockingRepository {
        entered: Notify,
        state_calls: AtomicUsize,
        pool_calls: AtomicUsize,
    }

    #[async_trait]
    impl ControlPlaneStateRepository for BlockingRepository {
        async fn control_plane_state_snapshot(
            &self,
            _request: ControlPlaneStateSnapshotRequest,
        ) -> Result<ControlPlaneStateSnapshot, automata_ci_store::StoreError> {
            self.state_calls.fetch_add(1, Ordering::Relaxed);
            self.entered.notify_one();
            std::future::pending().await
        }

        fn database_pool_snapshot(
            &self,
        ) -> Result<DatabasePoolSnapshot, automata_ci_store::StoreError> {
            self.pool_calls.fetch_add(1, Ordering::Relaxed);
            Ok(DatabasePoolSnapshot::default())
        }
    }

    fn registered() -> (Metrics, ControlPlaneStateMetrics) {
        let mut builder = MetricsBuilder::new(BuildInfo::new(
            ProcessRole::ControlPlane,
            "1.2.3-test",
            "unknown",
        ))
        .expect("valid metrics foundation");
        let state = ControlPlaneStateMetrics::register(builder.registry_mut());
        (builder.finish(ExporterLimits::default()), state)
    }

    fn snapshot(value: u64) -> Result<ControlPlaneStateSnapshot, ControlPlaneStateValueError> {
        let mut runs = WorkflowRunCounts::default();
        runs.set(WorkflowRunStatus::InProgress, value);
        let mut attempts = JobAttemptCounts::default();
        attempts.set(JobLifecycle::Running, value);
        let mut runners = RunnerCounts::default();
        runners.set(
            RunnerObservedState::Online,
            RunnerDesiredState::Active,
            value,
        );
        let mut sessions = RunnerSessionCounts::default();
        sessions.set(RunnerSessionState::Live, value);
        let mut leases = LeaseCounts::default();
        leases.set(LeaseState::Active, value);
        let mut artifacts = ArtifactCounts::default();
        for state in ArtifactState::ALL {
            artifacts.set(state, value);
        }
        let mut reservations = ArtifactReservations::default();
        for (kind, oldest_at) in [
            (ArtifactReservationKind::Block, UnixMillis::new(3_000)),
            (ArtifactReservationKind::Manifest, UnixMillis::new(4_000)),
        ] {
            reservations.set(kind, value, (value > 0).then_some(oldest_at))?;
        }
        let mut cleanup = BuiltinSecretCleanupCounts::default();
        for (status, oldest_created_at) in [
            (BuiltinSecretCleanupStatus::Pending, UnixMillis::new(2_600)),
            (
                BuiltinSecretCleanupStatus::InProgress,
                UnixMillis::new(2_700),
            ),
            (
                BuiltinSecretCleanupStatus::DeadLetter,
                UnixMillis::new(2_800),
            ),
        ] {
            cleanup.set(status, value, (value > 0).then_some(oldest_created_at))?;
        }
        ControlPlaneStateSnapshot::new(
            runs,
            attempts,
            runners,
            sessions,
            value,
            (value > 0).then(|| UnixMillis::new(1_000)),
            leases,
            value,
            (value > 0).then(|| UnixMillis::new(2_000)),
            value,
            (value > 0).then(|| UnixMillis::new(2_500)),
            artifacts,
            reservations,
        )
        .map(|snapshot| snapshot.with_builtin_secret_cleanup(cleanup))
    }

    fn capacity_runner(tenant_id: &str, label: &str, occupied: bool) -> ControlPlaneCapacityRunner {
        let runner_id = RunnerId::new();
        let capabilities = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        );
        ControlPlaneCapacityRunner::try_new(
            tenant_id.to_owned(),
            RunnerSessionFence::new(
                RunnerSessionId::new(),
                runner_id,
                RunnerGeneration::new(1).expect("generation"),
                SessionEpoch::new(1).expect("epoch"),
            ),
            None,
            [RoutingLabel::new(label).expect("routing label")],
            capabilities.clone(),
            capabilities,
            RunnerSlotCount::new(1).expect("slot count"),
            occupied.then(|| StableRunnerSlot::new(1).expect("stable slot")),
        )
        .expect("capacity runner")
    }

    fn capacity_candidate(
        tenant_id: &str,
        label: &str,
        queued_at: i64,
    ) -> ControlPlaneCapacityCandidate {
        ControlPlaneCapacityCandidate::new(
            tenant_id.to_owned(),
            AttemptId::new(),
            JobId::new(),
            UnixMillis::new(queued_at),
            RunnerRequirements::default()
                .with_labels([RunnerLabel::new(label).expect("runner label")])
                .with_operating_system(OperatingSystem::Linux)
                .with_architecture(Architecture::X86_64),
        )
    }

    #[test]
    fn compatible_capacity_is_exact_tenant_scoped_and_uses_effective_slot_state() {
        let durable = snapshot(3)
            .expect("base snapshot")
            .with_logical_orchestration(
                WorkflowPlanV2RunCounts::default(),
                LogicalJobCounts::default(),
                LogicalActivationCounts::default(),
                0,
                0,
                3,
                Some(UnixMillis::new(100)),
                vec![
                    capacity_candidate("tenant-a", "linux", 100),
                    capacity_candidate("tenant-a", "gpu", 200),
                    capacity_candidate("tenant-b", "linux", 300),
                ],
                vec![
                    capacity_runner("tenant-a", "linux", true),
                    capacity_runner("tenant-b", "linux", false),
                ],
            )
            .expect("complete bounded capacity snapshot");
        let capacity = compatible_capacity_snapshot(&durable, UnixMillis::new(1_000))
            .expect("valid effective scheduler inputs");
        assert_eq!(capacity.blocked, [1, 1]);
        assert_eq!(
            capacity.oldest_at,
            [Some(UnixMillis::new(200)), Some(UnixMillis::new(100))]
        );
    }

    #[test]
    fn schema_is_exact_closed_and_preinitialized() {
        let (exporter, _state) = registered();
        let exposition = exporter.encode_openmetrics().expect("bounded exposition");
        let exposition = exposition.as_str();
        let families = exposition
            .lines()
            .filter_map(|line| line.strip_prefix("# TYPE "))
            .filter_map(|line| line.split_once(' ').map(|(name, _kind)| name))
            .filter(|name| {
                name.starts_with("automata_ci_control_plane_state_sampler_")
                    || name.starts_with("automata_ci_control_plane_workflow_runs")
                    || name.starts_with("automata_ci_control_plane_workflow_plan_v2_runs")
                    || name.starts_with("automata_ci_control_plane_logical_")
                    || name.starts_with("automata_ci_control_plane_eligible_queue_")
                    || name.starts_with("automata_ci_control_plane_job_attempts")
                    || name.starts_with("automata_ci_control_plane_runners")
                    || name.starts_with("automata_ci_control_plane_runner_sessions")
                    || name.starts_with("automata_ci_control_plane_queue_")
                    || name.starts_with("automata_ci_control_plane_leases")
                    || name.starts_with("automata_ci_control_plane_commands_")
                    || name.starts_with("automata_ci_control_plane_cancellation_intents_")
                    || name.starts_with("automata_ci_control_plane_builtin_secret_cleanup_")
                    || name.starts_with("automata_ci_control_plane_artifact")
                    || name.starts_with("automata_ci_postgres_pool_")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            families,
            [
                "automata_ci_control_plane_commands_oldest_timestamp_seconds",
                "automata_ci_control_plane_commands_pending",
                "automata_ci_control_plane_cancellation_intents_oldest_timestamp_seconds",
                "automata_ci_control_plane_cancellation_intents_pending",
                "automata_ci_control_plane_builtin_secret_cleanup_oldest_created_timestamp_seconds",
                "automata_ci_control_plane_builtin_secret_cleanup_operations",
                "automata_ci_control_plane_artifact_reservation_oldest_timestamp_seconds",
                "automata_ci_control_plane_artifact_reservations",
                "automata_ci_control_plane_artifacts",
                "automata_ci_control_plane_job_attempts",
                "automata_ci_control_plane_logical_activation_oldest_timestamp_seconds",
                "automata_ci_control_plane_logical_activation_publications",
                "automata_ci_control_plane_logical_activations",
                "automata_ci_control_plane_logical_jobs",
                "automata_ci_control_plane_logical_materialized_instances",
                "automata_ci_control_plane_leases",
                "automata_ci_control_plane_eligible_queue_blocked_jobs",
                "automata_ci_control_plane_eligible_queue_blocked_oldest_timestamp_seconds",
                "automata_ci_control_plane_queue_jobs",
                "automata_ci_control_plane_queue_oldest_timestamp_seconds",
                "automata_ci_control_plane_runner_sessions",
                "automata_ci_control_plane_runners",
                "automata_ci_control_plane_state_sampler_duration_seconds",
                "automata_ci_control_plane_state_sampler_healthy",
                "automata_ci_control_plane_state_sampler_last_success_timestamp_seconds",
                "automata_ci_control_plane_state_sampler_runs",
                "automata_ci_control_plane_workflow_runs",
                "automata_ci_control_plane_workflow_plan_v2_runs",
                "automata_ci_postgres_pool_connections",
                "automata_ci_postgres_pool_max_connections",
            ]
            .into_iter()
            .collect()
        );
        let state_series = exposition
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_once(' ').map(|(sample, _value)| sample))
            .filter(|sample| {
                sample.starts_with("automata_ci_control_plane_state_sampler_")
                    || sample.starts_with("automata_ci_control_plane_workflow_runs")
                    || sample.starts_with("automata_ci_control_plane_workflow_plan_v2_runs")
                    || sample.starts_with("automata_ci_control_plane_logical_")
                    || sample.starts_with("automata_ci_control_plane_eligible_queue_")
                    || sample.starts_with("automata_ci_control_plane_job_attempts")
                    || sample.starts_with("automata_ci_control_plane_runners")
                    || sample.starts_with("automata_ci_control_plane_runner_sessions")
                    || sample.starts_with("automata_ci_control_plane_queue_")
                    || sample.starts_with("automata_ci_control_plane_leases")
                    || sample.starts_with("automata_ci_control_plane_commands_")
                    || sample.starts_with("automata_ci_control_plane_cancellation_intents_")
                    || sample.starts_with("automata_ci_control_plane_builtin_secret_cleanup_")
                    || sample.starts_with("automata_ci_control_plane_artifact")
                    || sample.starts_with("automata_ci_postgres_pool_")
            })
            .count();
        assert_eq!(state_series, 126);
        for private_label in [
            "tenant_id=",
            "runner_id=",
            "attempt_id=",
            "session_id=",
            "operation_id=",
            "provider_id=",
            "cleanup_kind=",
            "failure=",
            "failure_kind=",
            "last_failure_kind=",
        ] {
            assert!(!exposition.contains(private_label));
        }
    }

    #[tokio::test]
    async fn success_atomically_replaces_and_error_retains_last_good_without_scrape_io() {
        let (exporter, state) = registered();
        let source = Arc::new(FakeRepository::new(snapshot(3).expect("snapshot")));
        let repository: Arc<dyn ControlPlaneStateRepository> = source.clone();
        let sampler = state.sampler(repository);
        sampler.refresh_now().await;
        assert_eq!(source.state_calls.load(Ordering::Relaxed), 1);
        assert_eq!(source.pool_calls.load(Ordering::Relaxed), 1);

        let first = exporter.encode_openmetrics().expect("first scrape");
        let second = exporter.encode_openmetrics().expect("second scrape");
        assert_eq!(source.state_calls.load(Ordering::Relaxed), 1);
        assert_eq!(source.pool_calls.load(Ordering::Relaxed), 1);
        for exposition in [first.as_str(), second.as_str()] {
            assert!(
                exposition
                    .contains("automata_ci_control_plane_workflow_runs{status=\"in_progress\"} 3")
            );
            assert!(
                exposition
                    .contains("automata_ci_control_plane_job_attempts{lifecycle=\"running\"} 3")
            );
            assert!(
                exposition.contains("automata_ci_control_plane_queue_jobs{state=\"queued\"} 3")
            );
            assert!(
                exposition.contains("automata_ci_control_plane_cancellation_intents_pending 3")
            );
            assert!(exposition.contains(
                "automata_ci_control_plane_builtin_secret_cleanup_operations{status=\"pending\"} 3"
            ));
            assert!(exposition.contains(
                "automata_ci_control_plane_builtin_secret_cleanup_oldest_created_timestamp_seconds{status=\"dead_letter\"} 2.8"
            ));
            assert!(
                exposition.contains(
                    "automata_ci_control_plane_artifacts{state=\"publication_reserved\"} 3"
                )
            );
            assert!(
                exposition
                    .contains("automata_ci_control_plane_artifact_reservations{kind=\"block\"} 3")
            );
            assert!(
                exposition.contains("automata_ci_postgres_pool_connections{state=\"in_use\"} 5")
            );
            assert!(exposition.contains("automata_ci_control_plane_state_sampler_healthy 1"));
        }

        source.enqueue(snapshot(9).expect("replacement snapshot"));
        source.fail.store(true, Ordering::Relaxed);
        sampler.refresh_now().await;
        let failed = exporter
            .encode_openmetrics()
            .expect("failed-refresh scrape");
        assert!(
            failed
                .as_str()
                .contains("automata_ci_control_plane_workflow_runs{status=\"in_progress\"} 3")
        );
        assert!(
            !failed
                .as_str()
                .contains("automata_ci_control_plane_workflow_runs{status=\"in_progress\"} 9")
        );
        assert!(
            failed
                .as_str()
                .contains("automata_ci_control_plane_cancellation_intents_pending 3")
        );
        assert!(
            !failed
                .as_str()
                .contains("automata_ci_control_plane_cancellation_intents_pending 9")
        );
        assert!(
            failed
                .as_str()
                .contains("automata_ci_control_plane_artifacts{state=\"publication_reserved\"} 3")
        );
        assert!(
            !failed
                .as_str()
                .contains("automata_ci_control_plane_artifacts{state=\"publication_reserved\"} 9")
        );
        assert!(
            failed
                .as_str()
                .contains("automata_ci_control_plane_state_sampler_healthy 0")
        );
        assert!(
            failed.as_str().contains(
                "automata_ci_control_plane_state_sampler_runs_total{outcome=\"success\"} 1"
            )
        );
        assert!(
            failed.as_str().contains(
                "automata_ci_control_plane_state_sampler_runs_total{outcome=\"error\"} 1"
            )
        );
        assert_eq!(source.state_calls.load(Ordering::Relaxed), 2);
        assert_eq!(source.pool_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn sampler_attempts_immediately_and_cancels_promptly() {
        let (_exporter, state) = registered();
        let source = Arc::new(FakeRepository::new(snapshot(1).expect("snapshot")));
        let repository: Arc<dyn ControlPlaneStateRepository> = source.clone();
        let sampler = state.sampler(repository);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            sampler
                .run_until_cancelled(task_cancellation.cancelled_owned())
                .await;
        });
        tokio::time::timeout(Duration::from_millis(250), async {
            while source.state_calls.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("immediate first attempt");
        cancellation.cancel();
        tokio::time::timeout(Duration::from_millis(250), task)
            .await
            .expect("sampler cancellation")
            .expect("sampler task");

        let (_exporter, state) = registered();
        let source = Arc::new(FakeRepository::new(snapshot(1).expect("snapshot")));
        let repository: Arc<dyn ControlPlaneStateRepository> = source.clone();
        state
            .sampler(repository)
            .run_until_cancelled(std::future::ready(()))
            .await;
        assert_eq!(source.state_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cancellation_drops_an_in_flight_backend_snapshot() {
        let (exporter, state) = registered();
        let source = Arc::new(BlockingRepository::default());
        let repository: Arc<dyn ControlPlaneStateRepository> = source.clone();
        let sampler = state.sampler(repository);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            sampler
                .run_until_cancelled(task_cancellation.cancelled_owned())
                .await;
        });
        tokio::time::timeout(Duration::from_millis(250), source.entered.notified())
            .await
            .expect("sampler entered backend call");
        cancellation.cancel();
        tokio::time::timeout(Duration::from_millis(250), task)
            .await
            .expect("in-flight sampler cancellation")
            .expect("sampler task");
        assert_eq!(source.state_calls.load(Ordering::Relaxed), 1);
        assert_eq!(source.pool_calls.load(Ordering::Relaxed), 0);
        let exposition = exporter
            .encode_openmetrics()
            .expect("cancelled-refresh scrape");
        assert!(exposition.as_str().contains(
            "automata_ci_control_plane_state_sampler_runs_total{outcome=\"cancelled\"} 1"
        ));
        assert!(
            exposition
                .as_str()
                .contains("automata_ci_control_plane_state_sampler_healthy 0")
        );
    }
}
