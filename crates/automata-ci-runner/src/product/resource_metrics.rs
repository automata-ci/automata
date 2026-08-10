use std::{
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::AtomicU64,
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_metrics::{Counter, Family, Gauge, Registry, Unit};
use prometheus_client::{encoding::EncodeLabelSet, metrics::counter::Counter as PrometheusCounter};

const CGROUP_FS_ROOT: &str = "/sys/fs/cgroup";
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(10);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CGROUP_PATH_BYTES: usize = 4_096;
const MAX_FILE_BYTES: u64 = 256 * 1_024;
const MAX_STAT_LINES: usize = 512;
const MAX_LINE_BYTES: usize = 1_024;
const MAX_IO_DEVICES: usize = 256;

type FloatCounter = PrometheusCounter<f64, AtomicU64>;

#[derive(Clone)]
pub(super) struct ResourceMetricsSampler {
    worker: ResourceSnapshotWorker,
    metrics: ResourceMetricHandles,
    previous: Arc<Mutex<RawCounters>>,
    refreshes: Family<RefreshLabels, Counter>,
    healthy: Gauge,
    last_success_timestamp: Gauge,
}

impl fmt::Debug for ResourceMetricsSampler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceMetricsSampler")
            .finish_non_exhaustive()
    }
}

impl ResourceMetricsSampler {
    pub(super) fn register(registry: &mut Registry, runner_cgroup: Option<String>) -> Self {
        let worker = runner_cgroup
            .and_then(|cgroup| SystemCgroupSnapshotSource::new(&cgroup).ok())
            .map_or_else(
                || ResourceSnapshotWorker::Unavailable,
                |source| ResourceSnapshotWorker::start(Arc::new(source)),
            );
        Self::register_with_worker(registry, worker)
    }

    #[cfg(test)]
    fn register_with_source(
        registry: &mut Registry,
        source: Arc<dyn CgroupSnapshotSource>,
    ) -> Self {
        Self::register_with_worker(registry, ResourceSnapshotWorker::start(source))
    }

    fn register_with_worker(registry: &mut Registry, worker: ResourceSnapshotWorker) -> Self {
        let refreshes = Family::<RefreshLabels, Counter>::default();
        for outcome in ["success", "error", "timeout"] {
            refreshes
                .get_or_create(&RefreshLabels { outcome })
                .inc_by(0);
        }
        registry.register(
            "runner_cgroup_snapshot_refreshes",
            "Runner-owned cgroup-v2 aggregate snapshot refreshes by bounded outcome",
            refreshes.clone(),
        );

        let healthy = Gauge::default();
        registry.register(
            "runner_cgroup_snapshot_healthy",
            "Whether the latest runner-owned cgroup-v2 aggregate snapshot refresh succeeded",
            healthy.clone(),
        );

        let last_success_timestamp = Gauge::default();
        registry.register_with_unit(
            "runner_cgroup_snapshot_last_success_timestamp",
            "Unix timestamp of the latest successful runner-owned cgroup-v2 aggregate snapshot refresh",
            Unit::Seconds,
            last_success_timestamp.clone(),
        );

        Self {
            worker,
            metrics: ResourceMetricHandles::register(registry),
            previous: Arc::new(Mutex::new(RawCounters::default())),
            refreshes,
            healthy,
            last_success_timestamp,
        }
    }

    pub(super) async fn run_until_cancelled(self, shutdown: tokio_util::sync::CancellationToken) {
        self.refresh_with_timeout(SNAPSHOT_TIMEOUT).await;
        let first_refresh = tokio::time::Instant::now() + SNAPSHOT_INTERVAL;
        let mut ticker = tokio::time::interval_at(first_refresh, SNAPSHOT_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = ticker.tick() => self.refresh_with_timeout(SNAPSHOT_TIMEOUT).await,
            }
        }
    }

    async fn refresh_with_timeout(&self, timeout: Duration) {
        let outcome = match self.worker.read(timeout).await {
            Err(WorkerReadError::Timeout) => RefreshOutcome::Timeout,
            Err(WorkerReadError::Error | WorkerReadError::Unavailable) => RefreshOutcome::Error,
            Ok(snapshot) => match self.apply(snapshot, SystemTime::now()) {
                Ok(()) => RefreshOutcome::Success,
                Err(_snapshot_error) => RefreshOutcome::Error,
            },
        };
        self.healthy
            .set(i64::from(outcome == RefreshOutcome::Success));
        self.refreshes
            .get_or_create(&RefreshLabels {
                outcome: outcome.label(),
            })
            .inc();
    }

    fn apply(&self, snapshot: CgroupSnapshot, sampled_at: SystemTime) -> Result<(), SnapshotError> {
        let timestamp = sampled_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SnapshotError::Invalid)?
            .as_secs();
        let mut previous = self.previous.lock().map_err(|_| SnapshotError::State)?;

        self.metrics.cpu_usage_seconds.inc_by(micros_to_seconds(
            previous.cpu_usage_micros.delta(snapshot.cpu_usage_micros),
        ));
        self.metrics.cpu_throttled_seconds.inc_by(micros_to_seconds(
            previous
                .cpu_throttled_micros
                .delta(snapshot.cpu_throttled_micros),
        ));
        self.metrics
            .cpu_periods
            .inc_by(previous.cpu_periods.delta(snapshot.cpu_periods));
        self.metrics.cpu_throttled_periods.inc_by(
            previous
                .cpu_throttled_periods
                .delta(snapshot.cpu_throttled_periods),
        );
        for (index, direction) in ["read", "write"].into_iter().enumerate() {
            self.metrics
                .io_bytes
                .get_or_create(&DirectionLabels { direction })
                .inc_by(previous.io_bytes[index].delta(snapshot.io_bytes[index]));
            self.metrics
                .io_operations
                .get_or_create(&DirectionLabels { direction })
                .inc_by(previous.io_operations[index].delta(snapshot.io_operations[index]));
        }
        for (index, event) in ["oom", "oom_kill", "oom_group_kill"]
            .into_iter()
            .enumerate()
        {
            self.metrics
                .oom_events
                .get_or_create(&OomEventLabels { event })
                .inc_by(previous.oom_events[index].delta(snapshot.oom_events[index]));
        }

        self.metrics
            .memory_current_bytes
            .set(saturating_i64(snapshot.memory_current_bytes));
        self.metrics
            .memory_peak_bytes
            .set(saturating_i64(snapshot.memory_peak_bytes));
        self.metrics
            .pids_current
            .set(saturating_i64(snapshot.pids_current));
        self.last_success_timestamp.set(saturating_i64(timestamp));
        Ok(())
    }
}

#[derive(Clone)]
struct ResourceMetricHandles {
    cpu_usage_seconds: FloatCounter,
    cpu_throttled_seconds: FloatCounter,
    cpu_periods: Counter,
    cpu_throttled_periods: Counter,
    memory_current_bytes: Gauge,
    memory_peak_bytes: Gauge,
    pids_current: Gauge,
    io_bytes: Family<DirectionLabels, Counter>,
    io_operations: Family<DirectionLabels, Counter>,
    oom_events: Family<OomEventLabels, Counter>,
}

impl ResourceMetricHandles {
    fn register(registry: &mut Registry) -> Self {
        let cpu_usage_seconds = FloatCounter::default();
        registry.register_with_unit(
            "runner_cgroup_cpu_usage",
            "Process-observed aggregate CPU time consumed in the runner-owned cgroup-v2 boundary",
            Unit::Seconds,
            cpu_usage_seconds.clone(),
        );
        let cpu_throttled_seconds = FloatCounter::default();
        registry.register_with_unit(
            "runner_cgroup_cpu_throttled",
            "Process-observed aggregate CPU time throttled in the runner-owned cgroup-v2 boundary",
            Unit::Seconds,
            cpu_throttled_seconds.clone(),
        );
        let cpu_periods = Counter::default();
        registry.register(
            "runner_cgroup_cpu_periods",
            "Process-observed aggregate CPU scheduler periods in the runner-owned cgroup-v2 boundary",
            cpu_periods.clone(),
        );
        let cpu_throttled_periods = Counter::default();
        registry.register(
            "runner_cgroup_cpu_throttled_periods",
            "Process-observed aggregate throttled CPU scheduler periods in the runner-owned cgroup-v2 boundary",
            cpu_throttled_periods.clone(),
        );

        let memory_current_bytes = Gauge::default();
        registry.register_with_unit(
            "runner_cgroup_memory_current",
            "Current aggregate memory charged to the runner-owned cgroup-v2 boundary",
            Unit::Bytes,
            memory_current_bytes.clone(),
        );
        let memory_peak_bytes = Gauge::default();
        registry.register_with_unit(
            "runner_cgroup_memory_peak",
            "Peak aggregate memory charged to the runner-owned cgroup-v2 boundary",
            Unit::Bytes,
            memory_peak_bytes.clone(),
        );
        let pids_current = Gauge::default();
        registry.register(
            "runner_cgroup_pids_current",
            "Current aggregate process count in the runner-owned cgroup-v2 boundary",
            pids_current.clone(),
        );

        let io_bytes = Family::<DirectionLabels, Counter>::default();
        let io_operations = Family::<DirectionLabels, Counter>::default();
        for direction in ["read", "write"] {
            io_bytes
                .get_or_create(&DirectionLabels { direction })
                .inc_by(0);
            io_operations
                .get_or_create(&DirectionLabels { direction })
                .inc_by(0);
        }
        registry.register_with_unit(
            "runner_cgroup_io",
            "Process-observed aggregate block IO bytes in the runner-owned cgroup-v2 boundary by direction",
            Unit::Bytes,
            io_bytes.clone(),
        );
        registry.register(
            "runner_cgroup_io_operations",
            "Process-observed aggregate block IO operations in the runner-owned cgroup-v2 boundary by direction",
            io_operations.clone(),
        );

        let oom_events = Family::<OomEventLabels, Counter>::default();
        for event in ["oom", "oom_kill", "oom_group_kill"] {
            oom_events
                .get_or_create(&OomEventLabels { event })
                .inc_by(0);
        }
        registry.register(
            "runner_cgroup_memory_oom_events",
            "Process-observed aggregate memory OOM events in the runner-owned cgroup-v2 boundary by bounded event",
            oom_events.clone(),
        );

        Self {
            cpu_usage_seconds,
            cpu_throttled_seconds,
            cpu_periods,
            cpu_throttled_periods,
            memory_current_bytes,
            memory_peak_bytes,
            pids_current,
            io_bytes,
            io_operations,
            oom_events,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct DirectionLabels {
    direction: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct OomEventLabels {
    event: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RefreshLabels {
    outcome: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefreshOutcome {
    Success,
    Error,
    Timeout,
}

impl RefreshOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MonotonicRawCounter {
    previous: Option<u64>,
}

impl MonotonicRawCounter {
    fn delta(&mut self, current: u64) -> u64 {
        let delta = self.previous.map_or(0, |previous| {
            current.checked_sub(previous).unwrap_or(current)
        });
        self.previous = Some(current);
        delta
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RawCounters {
    cpu_usage_micros: MonotonicRawCounter,
    cpu_throttled_micros: MonotonicRawCounter,
    cpu_periods: MonotonicRawCounter,
    cpu_throttled_periods: MonotonicRawCounter,
    io_bytes: [MonotonicRawCounter; 2],
    io_operations: [MonotonicRawCounter; 2],
    oom_events: [MonotonicRawCounter; 3],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CgroupSnapshot {
    cpu_usage_micros: u64,
    cpu_throttled_micros: u64,
    cpu_periods: u64,
    cpu_throttled_periods: u64,
    memory_current_bytes: u64,
    memory_peak_bytes: u64,
    pids_current: u64,
    io_bytes: [u64; 2],
    io_operations: [u64; 2],
    oom_events: [u64; 3],
}

trait CgroupSnapshotSource: fmt::Debug + Send + Sync {
    fn read(&self) -> Result<CgroupSnapshot, SnapshotError>;
}

#[derive(Clone)]
enum ResourceSnapshotWorker {
    Active(SyncSender<ReadRequest>),
    Unavailable,
}

impl ResourceSnapshotWorker {
    fn start(source: Arc<dyn CgroupSnapshotSource>) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<ReadRequest>(1);
        let worker = thread::Builder::new()
            .name("automata-runner-cgroup-metrics".to_owned())
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    let _ignored = request.response.send(source.read());
                }
            });
        if worker.is_ok() {
            Self::Active(sender)
        } else {
            Self::Unavailable
        }
    }

    async fn read(&self, timeout: Duration) -> Result<CgroupSnapshot, WorkerReadError> {
        let Self::Active(sender) = self else {
            return Err(WorkerReadError::Unavailable);
        };
        let (response, received) = tokio::sync::oneshot::channel();
        match sender.try_send(ReadRequest { response }) {
            Ok(()) => {}
            Err(TrySendError::Full(_request)) => return Err(WorkerReadError::Timeout),
            Err(TrySendError::Disconnected(_request)) => return Err(WorkerReadError::Error),
        }
        match tokio::time::timeout(timeout, received).await {
            Err(_elapsed) => Err(WorkerReadError::Timeout),
            Ok(Err(_closed)) => Err(WorkerReadError::Error),
            Ok(Ok(Err(_snapshot_error))) => Err(WorkerReadError::Error),
            Ok(Ok(Ok(snapshot))) => Ok(snapshot),
        }
    }
}

impl fmt::Debug for ResourceSnapshotWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceSnapshotWorker")
            .finish_non_exhaustive()
    }
}

struct ReadRequest {
    response: tokio::sync::oneshot::Sender<Result<CgroupSnapshot, SnapshotError>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerReadError {
    Unavailable,
    Timeout,
    Error,
}

struct SystemCgroupSnapshotSource {
    directory: PathBuf,
}

impl SystemCgroupSnapshotSource {
    fn new(cgroup: &str) -> Result<Self, SnapshotError> {
        Ok(Self {
            directory: cgroup_directory(cgroup)?,
        })
    }

    fn read_file(&self, leaf: &'static str) -> Result<Vec<u8>, SnapshotError> {
        read_bounded(&self.directory.join(leaf))
    }
}

impl fmt::Debug for SystemCgroupSnapshotSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemCgroupSnapshotSource")
            .finish_non_exhaustive()
    }
}

impl CgroupSnapshotSource for SystemCgroupSnapshotSource {
    fn read(&self) -> Result<CgroupSnapshot, SnapshotError> {
        let cpu = parse_cpu_stat(&self.read_file("cpu.stat")?)?;
        let memory_current_bytes = parse_scalar(&self.read_file("memory.current")?)?;
        let memory_peak_bytes = parse_scalar(&self.read_file("memory.peak")?)?;
        let pids_current = parse_scalar(&self.read_file("pids.current")?)?;
        let io = parse_io_stat(&self.read_file("io.stat")?)?;
        let oom_events = parse_memory_events(&self.read_file("memory.events")?)?;
        Ok(CgroupSnapshot {
            cpu_usage_micros: cpu.usage_micros,
            cpu_throttled_micros: cpu.throttled_micros,
            cpu_periods: cpu.periods,
            cpu_throttled_periods: cpu.throttled_periods,
            memory_current_bytes,
            memory_peak_bytes,
            pids_current,
            io_bytes: io.bytes,
            io_operations: io.operations,
            oom_events,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotError {
    Read,
    TooLarge,
    Invalid,
    Overflow,
    State,
}

fn cgroup_directory(cgroup: &str) -> Result<PathBuf, SnapshotError> {
    let relative = cgroup.strip_prefix('/').ok_or(SnapshotError::Invalid)?;
    if relative.is_empty()
        || cgroup.len() > MAX_CGROUP_PATH_BYTES
        || cgroup.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(SnapshotError::Invalid);
    }
    let mut directory = PathBuf::from(CGROUP_FS_ROOT);
    for component in relative.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(SnapshotError::Invalid);
        }
        directory.push(component);
    }
    Ok(directory)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, SnapshotError> {
    let file = File::open(path).map_err(|_| SnapshotError::Read)?;
    read_bounded_reader(file)
}

fn read_bounded_reader(mut reader: impl Read) -> Result<Vec<u8>, SnapshotError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SnapshotError::Read)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    Ok(bytes)
}

fn parse_scalar(document: &[u8]) -> Result<u64, SnapshotError> {
    let text = std::str::from_utf8(document).map_err(|_| SnapshotError::Invalid)?;
    if text.len() > MAX_LINE_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    let mut fields = text.split_ascii_whitespace();
    let value = parse_u64(fields.next().ok_or(SnapshotError::Invalid)?)?;
    if fields.next().is_some() {
        return Err(SnapshotError::Invalid);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CpuStat {
    usage_micros: u64,
    throttled_micros: u64,
    periods: u64,
    throttled_periods: u64,
}

fn parse_cpu_stat(document: &[u8]) -> Result<CpuStat, SnapshotError> {
    let mut usage_micros = None;
    let mut throttled_micros = None;
    let mut periods = None;
    let mut throttled_periods = None;
    for line in bounded_lines(document)? {
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().ok_or(SnapshotError::Invalid)?;
        let value = parse_u64(fields.next().ok_or(SnapshotError::Invalid)?)?;
        if fields.next().is_some() {
            return Err(SnapshotError::Invalid);
        }
        match name {
            "usage_usec" => set_once(&mut usage_micros, value)?,
            "throttled_usec" => set_once(&mut throttled_micros, value)?,
            "nr_periods" => set_once(&mut periods, value)?,
            "nr_throttled" => set_once(&mut throttled_periods, value)?,
            _ => {}
        }
    }
    Ok(CpuStat {
        usage_micros: usage_micros.ok_or(SnapshotError::Invalid)?,
        throttled_micros: throttled_micros.ok_or(SnapshotError::Invalid)?,
        periods: periods.ok_or(SnapshotError::Invalid)?,
        throttled_periods: throttled_periods.ok_or(SnapshotError::Invalid)?,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct IoStat {
    bytes: [u64; 2],
    operations: [u64; 2],
}

fn parse_io_stat(document: &[u8]) -> Result<IoStat, SnapshotError> {
    let lines = bounded_lines(document)?;
    if lines.len() > MAX_IO_DEVICES {
        return Err(SnapshotError::TooLarge);
    }
    let mut devices = Vec::with_capacity(lines.len());
    let mut result = IoStat::default();
    for line in lines {
        let mut fields = line.split_ascii_whitespace();
        let device = fields.next().ok_or(SnapshotError::Invalid)?;
        validate_device(device)?;
        if devices.contains(&device) {
            return Err(SnapshotError::Invalid);
        }
        devices.push(device);

        let mut read_bytes = None;
        let mut write_bytes = None;
        let mut read_operations = None;
        let mut write_operations = None;
        for field in fields {
            let (name, encoded) = field.split_once('=').ok_or(SnapshotError::Invalid)?;
            let value = parse_u64(encoded)?;
            match name {
                "rbytes" => set_once(&mut read_bytes, value)?,
                "wbytes" => set_once(&mut write_bytes, value)?,
                "rios" => set_once(&mut read_operations, value)?,
                "wios" => set_once(&mut write_operations, value)?,
                _ => {}
            }
        }
        checked_add(
            &mut result.bytes[0],
            read_bytes.ok_or(SnapshotError::Invalid)?,
        )?;
        checked_add(
            &mut result.bytes[1],
            write_bytes.ok_or(SnapshotError::Invalid)?,
        )?;
        checked_add(
            &mut result.operations[0],
            read_operations.ok_or(SnapshotError::Invalid)?,
        )?;
        checked_add(
            &mut result.operations[1],
            write_operations.ok_or(SnapshotError::Invalid)?,
        )?;
    }
    Ok(result)
}

fn parse_memory_events(document: &[u8]) -> Result<[u64; 3], SnapshotError> {
    let mut oom = None;
    let mut oom_kill = None;
    let mut oom_group_kill = None;
    for line in bounded_lines(document)? {
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().ok_or(SnapshotError::Invalid)?;
        let value = parse_u64(fields.next().ok_or(SnapshotError::Invalid)?)?;
        if fields.next().is_some() {
            return Err(SnapshotError::Invalid);
        }
        match name {
            "oom" => set_once(&mut oom, value)?,
            "oom_kill" => set_once(&mut oom_kill, value)?,
            "oom_group_kill" => set_once(&mut oom_group_kill, value)?,
            _ => {}
        }
    }
    Ok([
        oom.ok_or(SnapshotError::Invalid)?,
        oom_kill.ok_or(SnapshotError::Invalid)?,
        oom_group_kill.unwrap_or(0),
    ])
}

fn bounded_lines(document: &[u8]) -> Result<Vec<&str>, SnapshotError> {
    let text = std::str::from_utf8(document).map_err(|_| SnapshotError::Invalid)?;
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            return Err(SnapshotError::Invalid);
        }
        if line.len() > MAX_LINE_BYTES || lines.len() == MAX_STAT_LINES {
            return Err(SnapshotError::TooLarge);
        }
        lines.push(line);
    }
    Ok(lines)
}

fn validate_device(device: &str) -> Result<(), SnapshotError> {
    let (major, minor) = device.split_once(':').ok_or(SnapshotError::Invalid)?;
    if major.is_empty()
        || minor.is_empty()
        || minor.contains(':')
        || major.parse::<u32>().is_err()
        || minor.parse::<u32>().is_err()
    {
        return Err(SnapshotError::Invalid);
    }
    Ok(())
}

fn set_once(target: &mut Option<u64>, value: u64) -> Result<(), SnapshotError> {
    if target.replace(value).is_some() {
        return Err(SnapshotError::Invalid);
    }
    Ok(())
}

fn checked_add(target: &mut u64, value: u64) -> Result<(), SnapshotError> {
    *target = target.checked_add(value).ok_or(SnapshotError::Overflow)?;
    Ok(())
}

fn parse_u64(value: &str) -> Result<u64, SnapshotError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SnapshotError::Invalid);
    }
    value.parse().map_err(|_| SnapshotError::Overflow)
}

fn micros_to_seconds(micros: u64) -> f64 {
    Duration::from_micros(micros).as_secs_f64()
}

fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, fmt::Write as _, io::Cursor};

    use super::*;

    #[test]
    fn parses_one_bounded_aggregate_snapshot_without_retaining_device_labels() {
        let cpu = parse_cpu_stat(
            b"usage_usec 1200000\nuser_usec 1000000\nsystem_usec 200000\nnr_periods 90\nnr_throttled 7\nthrottled_usec 23000\n",
        )
        .expect("cpu stat");
        assert_eq!(
            cpu,
            CpuStat {
                usage_micros: 1_200_000,
                throttled_micros: 23_000,
                periods: 90,
                throttled_periods: 7,
            }
        );
        let io = parse_io_stat(
            b"8:0 rbytes=10 wbytes=20 rios=2 wios=3 dbytes=4 dios=1\n259:1 rbytes=30 wbytes=40 rios=5 wios=6\n",
        )
        .expect("io stat");
        assert_eq!(
            io,
            IoStat {
                bytes: [40, 60],
                operations: [7, 9],
            }
        );
        assert_eq!(
            parse_memory_events(b"low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\noom_group_kill 6\n"),
            Ok([4, 5, 6])
        );
    }

    #[test]
    fn parsers_reject_ambiguous_unbounded_or_overflowing_documents() {
        assert_eq!(
            parse_cpu_stat(
                b"usage_usec 1\nusage_usec 2\nnr_periods 3\nnr_throttled 4\nthrottled_usec 5\n"
            ),
            Err(SnapshotError::Invalid)
        );
        assert_eq!(
            parse_io_stat(b"8:0 rbytes=18446744073709551615 wbytes=1 rios=1 wios=1\n8:1 rbytes=1 wbytes=1 rios=1 wios=1\n"),
            Err(SnapshotError::Overflow)
        );
        let mut devices = String::new();
        for index in 0..=MAX_IO_DEVICES {
            writeln!(devices, "8:{index} rbytes=1 wbytes=1 rios=1 wios=1")
                .expect("write in-memory fixture");
        }
        assert_eq!(
            parse_io_stat(devices.as_bytes()),
            Err(SnapshotError::TooLarge)
        );
        assert_eq!(parse_scalar(b"1 2\n"), Err(SnapshotError::Invalid));
        assert_eq!(
            read_bounded_reader(Cursor::new(vec![
                b'x';
                usize::try_from(MAX_FILE_BYTES)
                    .expect("file cap")
                    + 1
            ])),
            Err(SnapshotError::TooLarge)
        );
        let lines = "oom 1\n".repeat(MAX_STAT_LINES + 1);
        assert_eq!(
            parse_memory_events(lines.as_bytes()),
            Err(SnapshotError::TooLarge)
        );
        let line = format!("{} 1\n", "x".repeat(MAX_LINE_BYTES));
        assert_eq!(
            parse_memory_events(line.as_bytes()),
            Err(SnapshotError::TooLarge)
        );
        assert_eq!(
            cgroup_directory("/runner.service/../other"),
            Err(SnapshotError::Invalid)
        );
    }

    #[test]
    fn debug_output_never_exposes_the_cgroup_path() {
        let source = SystemCgroupSnapshotSource::new(
            "/private-runner-sentinel.service/private-supervisor-sentinel.scope",
        )
        .expect("syntactically valid cgroup");
        let debug = format!("{source:?}");
        assert!(!debug.contains("private-runner-sentinel"));
        assert!(!debug.contains("private-supervisor-sentinel"));
    }

    #[tokio::test]
    async fn cached_metrics_remain_monotonic_when_raw_job_aggregates_decrease() {
        let source = Arc::new(SequenceSource::new([
            Ok(snapshot(10, 100, 1_000)),
            Ok(snapshot(4, 40, 400)),
            Ok(snapshot(9, 90, 900)),
        ]));
        let mut registry = Registry::default();
        let sampler = ResourceMetricsSampler::register_with_source(&mut registry, source);
        for _ in 0..3 {
            sampler.refresh_with_timeout(Duration::from_secs(1)).await;
        }

        assert_eq!(sampler.metrics.cpu_periods.get(), 9);
        assert_eq!(
            sampler
                .metrics
                .io_bytes
                .get_or_create(&DirectionLabels { direction: "read" })
                .get(),
            90
        );
        assert_eq!(sampler.metrics.memory_current_bytes.get(), 900);
        assert_eq!(sampler.healthy.get(), 1);
        assert!(sampler.last_success_timestamp.get() > 0);
        assert_eq!(
            sampler
                .refreshes
                .get_or_create(&RefreshLabels { outcome: "success" })
                .get(),
            3
        );
    }

    #[tokio::test]
    async fn timeout_and_error_are_bounded_and_keep_the_last_good_snapshot() {
        let source = Arc::new(SequenceSource::new([
            Ok(snapshot(10, 100, 1_000)),
            Err(SnapshotError::Read),
        ]));
        let mut registry = Registry::default();
        let sampler = ResourceMetricsSampler::register_with_source(&mut registry, source);
        sampler.refresh_with_timeout(Duration::from_secs(1)).await;
        sampler.refresh_with_timeout(Duration::from_secs(1)).await;
        assert_eq!(sampler.healthy.get(), 0);
        assert_eq!(sampler.metrics.memory_current_bytes.get(), 1_000);
        assert_eq!(
            sampler
                .refreshes
                .get_or_create(&RefreshLabels { outcome: "error" })
                .get(),
            1
        );

        let mut registry = Registry::default();
        let sampler = ResourceMetricsSampler::register_with_source(
            &mut registry,
            Arc::new(SlowSource(Duration::from_millis(100))),
        );
        sampler.refresh_with_timeout(Duration::from_millis(5)).await;
        assert_eq!(sampler.healthy.get(), 0);
        assert_eq!(
            sampler
                .refreshes
                .get_or_create(&RefreshLabels { outcome: "timeout" })
                .get(),
            1
        );
    }

    fn snapshot(periods: u64, io_bytes: u64, memory: u64) -> CgroupSnapshot {
        CgroupSnapshot {
            cpu_usage_micros: periods * 1_000,
            cpu_throttled_micros: periods * 10,
            cpu_periods: periods,
            cpu_throttled_periods: periods / 2,
            memory_current_bytes: memory,
            memory_peak_bytes: memory * 2,
            pids_current: periods,
            io_bytes: [io_bytes, io_bytes * 2],
            io_operations: [periods, periods * 2],
            oom_events: [periods, periods / 2, periods / 4],
        }
    }

    #[derive(Debug)]
    struct SequenceSource {
        values: Mutex<VecDeque<Result<CgroupSnapshot, SnapshotError>>>,
    }

    impl SequenceSource {
        fn new(values: impl IntoIterator<Item = Result<CgroupSnapshot, SnapshotError>>) -> Self {
            Self {
                values: Mutex::new(values.into_iter().collect()),
            }
        }
    }

    impl CgroupSnapshotSource for SequenceSource {
        fn read(&self) -> Result<CgroupSnapshot, SnapshotError> {
            self.values
                .lock()
                .map_err(|_| SnapshotError::State)?
                .pop_front()
                .ok_or(SnapshotError::Read)?
        }
    }

    #[derive(Debug)]
    struct SlowSource(Duration);

    impl CgroupSnapshotSource for SlowSource {
        fn read(&self) -> Result<CgroupSnapshot, SnapshotError> {
            std::thread::sleep(self.0);
            Ok(snapshot(1, 1, 1))
        }
    }
}
