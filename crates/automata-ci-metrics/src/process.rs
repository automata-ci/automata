use std::{
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use std::{fs::File, io::Read as _, path::Path};

use prometheus_client::{
    encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder},
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Registry, Unit},
};

use crate::common::FloatGauge;

/// Fixed interval between process-resource snapshot refreshes.
pub const PROCESS_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(10);

#[cfg(target_os = "linux")]
const MAX_PROC_FILE_BYTES: u64 = 64 * 1_024;
#[cfg(target_os = "linux")]
const MAX_OPEN_FDS_TO_SCAN: u64 = 1_048_576;

type FloatCounter = Counter<f64, AtomicU64>;
type UnsignedGauge = Gauge<u64, AtomicU64>;

/// Cached standard process metrics and their off-scrape Linux sampler.
///
/// Clones refer to the same fixed metric handles. Product composition should
/// supervise exactly one [`Self::run_until_cancelled`] future while the
/// corresponding metrics listener is enabled.
#[derive(Clone)]
pub struct ProcessMetricsSampler {
    source: Arc<dyn ProcessSnapshotSource>,
    metrics: ProcessMetricHandles,
    refreshes: Family<RefreshLabels, Counter>,
    healthy: Gauge,
    last_success_timestamp: FloatGauge,
}

impl fmt::Debug for ProcessMetricsSampler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessMetricsSampler")
            .finish_non_exhaustive()
    }
}

impl ProcessMetricsSampler {
    pub(crate) fn register(root_registry: &mut Registry) -> Self {
        register_process_start_time(root_registry);

        let metrics = ProcessMetricHandles::register(root_registry);
        let registry = root_registry.sub_registry_with_prefix(crate::METRIC_NAMESPACE);

        let refreshes = Family::<RefreshLabels, Counter>::default();
        for outcome in RefreshOutcome::ALL {
            let _ = refreshes.get_or_create(&RefreshLabels { outcome });
        }
        registry.register(
            "metrics_process_snapshot_refreshes",
            "Process resource snapshot refresh attempts by bounded outcome",
            refreshes.clone(),
        );

        let healthy = Gauge::default();
        registry.register(
            "metrics_process_snapshot_healthy",
            "Whether the most recent process resource snapshot refresh succeeded",
            healthy.clone(),
        );

        let last_success_timestamp = FloatGauge::default();
        registry.register_with_unit(
            "metrics_process_snapshot_last_success_timestamp",
            "Unix timestamp of the last successful process resource snapshot refresh",
            Unit::Seconds,
            last_success_timestamp.clone(),
        );

        Self {
            source: Arc::new(SystemProcessSnapshotSource),
            metrics,
            refreshes,
            healthy,
            last_success_timestamp,
        }
    }

    /// Refreshes the cached snapshot every ten seconds until shutdown.
    ///
    /// The shutdown future should resolve when the product cancellation tree
    /// begins stopping. Refresh failures are represented by the sampler's
    /// bounded health metrics and never terminate this future; the last good
    /// standard process values remain available to scrapes.
    pub async fn run_until_cancelled<F>(self, shutdown: F)
    where
        F: Future<Output = ()> + Send,
    {
        self.run_until_cancelled_with_interval(shutdown, PROCESS_SNAPSHOT_INTERVAL)
            .await;
    }

    async fn run_until_cancelled_with_interval<F>(self, shutdown: F, interval: Duration)
    where
        F: Future<Output = ()> + Send,
    {
        let first_refresh = tokio::time::Instant::now() + interval;
        let mut ticker = tokio::time::interval_at(first_refresh, interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return,
                _ = ticker.tick() => self.refresh_at(SystemTime::now()),
            }
        }
    }

    pub(crate) fn refresh_at(&self, timestamp: SystemTime) {
        let result = self
            .source
            .read()
            .and_then(|snapshot| self.apply(snapshot, timestamp));
        let outcome = if result.is_ok() {
            self.healthy.set(1);
            RefreshOutcome::Success
        } else {
            self.healthy.set(0);
            RefreshOutcome::Error
        };
        self.refreshes
            .get_or_create(&RefreshLabels { outcome })
            .inc();
    }

    fn apply(&self, snapshot: ProcessSnapshot, timestamp: SystemTime) -> Result<(), SnapshotError> {
        if !snapshot.cpu_seconds.is_finite() || snapshot.cpu_seconds.is_sign_negative() {
            return Err(SnapshotError::Invalid);
        }
        let timestamp = timestamp
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SnapshotError::Invalid)?
            .as_secs_f64();
        self.metrics.set_cpu_seconds(snapshot.cpu_seconds)?;
        self.metrics
            .resident_memory_bytes
            .set(snapshot.resident_memory_bytes);
        self.metrics
            .virtual_memory_bytes
            .set(snapshot.virtual_memory_bytes);
        self.metrics.threads.set(snapshot.threads);
        self.metrics.open_fds.set(snapshot.open_fds);
        self.metrics.max_fds.set(snapshot.max_fds);
        self.last_success_timestamp.set(timestamp);
        Ok(())
    }

    #[cfg(test)]
    fn register_with_source(
        root_registry: &mut Registry,
        source: Arc<dyn ProcessSnapshotSource>,
    ) -> Self {
        let mut sampler = Self::register(root_registry);
        sampler.source = source;
        sampler
    }
}

#[derive(Clone, Debug)]
struct ProcessMetricHandles {
    cpu_seconds: FloatCounter,
    resident_memory_bytes: UnsignedGauge,
    virtual_memory_bytes: UnsignedGauge,
    threads: UnsignedGauge,
    open_fds: UnsignedGauge,
    max_fds: UnsignedGauge,
}

impl ProcessMetricHandles {
    fn register(root_registry: &mut Registry) -> Self {
        let cpu_seconds = FloatCounter::default();
        root_registry.register_with_unit(
            "process_cpu",
            "Total user and system CPU time spent in seconds",
            Unit::Seconds,
            cpu_seconds.clone(),
        );

        let resident_memory_bytes = UnsignedGauge::default();
        root_registry.register_with_unit(
            "process_resident_memory",
            "Resident memory size in bytes",
            Unit::Bytes,
            resident_memory_bytes.clone(),
        );

        let virtual_memory_bytes = UnsignedGauge::default();
        root_registry.register_with_unit(
            "process_virtual_memory",
            "Virtual memory size in bytes",
            Unit::Bytes,
            virtual_memory_bytes.clone(),
        );

        let threads = UnsignedGauge::default();
        root_registry.register(
            "process_threads",
            "Number of operating system threads in the process",
            threads.clone(),
        );

        let open_fds = UnsignedGauge::default();
        root_registry.register(
            "process_open_fds",
            "Number of open file descriptors",
            open_fds.clone(),
        );

        let max_fds = UnsignedGauge::default();
        root_registry.register(
            "process_max_fds",
            "Maximum number of open file descriptors",
            max_fds.clone(),
        );

        Self {
            cpu_seconds,
            resident_memory_bytes,
            virtual_memory_bytes,
            threads,
            open_fds,
            max_fds,
        }
    }

    fn set_cpu_seconds(&self, value: f64) -> Result<(), SnapshotError> {
        let atomic = self.cpu_seconds.inner();
        let mut current_bits = atomic.load(Ordering::Relaxed);
        loop {
            let current = f64::from_bits(current_bits);
            if value < current {
                return Err(SnapshotError::Invalid);
            }
            match atomic.compare_exchange_weak(
                current_bits,
                value.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current_bits = observed,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, EncodeLabelSet, Eq, Hash, PartialEq)]
struct RefreshLabels {
    outcome: RefreshOutcome,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RefreshOutcome {
    Success,
    Error,
}

impl RefreshOutcome {
    const ALL: [Self; 2] = [Self::Success, Self::Error];
}

impl EncodeLabelValue for RefreshOutcome {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> fmt::Result {
        use fmt::Write as _;

        encoder.write_str(match self {
            Self::Success => "success",
            Self::Error => "error",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ProcessSnapshot {
    cpu_seconds: f64,
    resident_memory_bytes: u64,
    virtual_memory_bytes: u64,
    threads: u64,
    open_fds: u64,
    max_fds: u64,
}

trait ProcessSnapshotSource: Send + Sync {
    fn read(&self) -> Result<ProcessSnapshot, SnapshotError>;
}

#[derive(Debug)]
struct SystemProcessSnapshotSource;

#[cfg(target_os = "linux")]
impl ProcessSnapshotSource for SystemProcessSnapshotSource {
    fn read(&self) -> Result<ProcessSnapshot, SnapshotError> {
        let process_stat = read_bounded_utf8(Path::new("/proc/self/stat"))?;
        let process_limits = read_bounded_utf8(Path::new("/proc/self/limits"))?;
        let open_fds = count_open_fds(Path::new("/proc/self/fd"))?;
        parse_linux_process_snapshot(
            &process_stat,
            &process_limits,
            open_fds,
            rustix::param::clock_ticks_per_second(),
            u64::try_from(rustix::param::page_size()).map_err(|_| SnapshotError::Invalid)?,
        )
    }
}

#[cfg(not(target_os = "linux"))]
impl ProcessSnapshotSource for SystemProcessSnapshotSource {
    fn read(&self) -> Result<ProcessSnapshot, SnapshotError> {
        Err(SnapshotError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotError {
    Unavailable,
    #[cfg(target_os = "linux")]
    Oversized,
    Invalid,
}

#[cfg(target_os = "linux")]
fn read_bounded_utf8(path: &Path) -> Result<String, SnapshotError> {
    let file = File::open(path).map_err(|_| SnapshotError::Unavailable)?;
    let mut bytes = Vec::new();
    file.take(MAX_PROC_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SnapshotError::Unavailable)?;
    if u64::try_from(bytes.len()).map_err(|_| SnapshotError::Oversized)? > MAX_PROC_FILE_BYTES {
        return Err(SnapshotError::Oversized);
    }
    String::from_utf8(bytes).map_err(|_| SnapshotError::Invalid)
}

#[cfg(target_os = "linux")]
fn count_open_fds(path: &Path) -> Result<u64, SnapshotError> {
    let entries = std::fs::read_dir(path).map_err(|_| SnapshotError::Unavailable)?;
    let mut count = 0_u64;
    for entry in entries {
        let _ = entry.map_err(|_| SnapshotError::Unavailable)?;
        count = count.checked_add(1).ok_or(SnapshotError::Oversized)?;
        if count > MAX_OPEN_FDS_TO_SCAN {
            return Err(SnapshotError::Oversized);
        }
    }
    Ok(count)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_process_snapshot(
    process_stat: &str,
    process_limits: &str,
    open_fds: u64,
    clock_ticks_per_second: u64,
    page_size: u64,
) -> Result<ProcessSnapshot, SnapshotError> {
    if clock_ticks_per_second == 0 || page_size == 0 {
        return Err(SnapshotError::Invalid);
    }
    let fields = linux_stat_fields(process_stat)?;
    let user_ticks = parse_stat_u64(&fields, 11)?;
    let system_ticks = parse_stat_u64(&fields, 12)?;
    let total_ticks = user_ticks
        .checked_add(system_ticks)
        .ok_or(SnapshotError::Invalid)?;
    let threads = parse_stat_u64(&fields, 17)?;
    let virtual_memory_bytes = parse_stat_u64(&fields, 20)?;
    let resident_pages = parse_stat_u64(&fields, 21)?;
    let resident_memory_bytes = resident_pages
        .checked_mul(page_size)
        .ok_or(SnapshotError::Invalid)?;
    let max_fds = parse_max_open_files(process_limits)?;
    let cpu_seconds = ticks_as_seconds(total_ticks, clock_ticks_per_second)?;

    Ok(ProcessSnapshot {
        cpu_seconds,
        resident_memory_bytes,
        virtual_memory_bytes,
        threads,
        open_fds,
        max_fds,
    })
}

#[cfg(any(target_os = "linux", test))]
fn ticks_as_seconds(ticks: u64, clock_ticks_per_second: u64) -> Result<f64, SnapshotError> {
    if clock_ticks_per_second == 0 {
        return Err(SnapshotError::Invalid);
    }
    let whole_seconds = ticks / clock_ticks_per_second;
    let remaining_ticks = ticks % clock_ticks_per_second;
    let nanoseconds = remaining_ticks
        .checked_mul(1_000_000_000)
        .ok_or(SnapshotError::Invalid)?
        .checked_div(clock_ticks_per_second)
        .ok_or(SnapshotError::Invalid)?;
    let nanoseconds = u32::try_from(nanoseconds).map_err(|_| SnapshotError::Invalid)?;
    Ok(Duration::new(whole_seconds, nanoseconds).as_secs_f64())
}

#[cfg(any(target_os = "linux", test))]
fn linux_stat_fields(process_stat: &str) -> Result<Vec<&str>, SnapshotError> {
    let (_, fields) = process_stat
        .trim_end()
        .rsplit_once(") ")
        .ok_or(SnapshotError::Invalid)?;
    let fields = fields.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() <= 21 {
        return Err(SnapshotError::Invalid);
    }
    Ok(fields)
}

#[cfg(any(target_os = "linux", test))]
fn parse_stat_u64(fields: &[&str], index: usize) -> Result<u64, SnapshotError> {
    fields
        .get(index)
        .ok_or(SnapshotError::Invalid)?
        .parse::<u64>()
        .map_err(|_| SnapshotError::Invalid)
}

#[cfg(any(target_os = "linux", test))]
fn parse_max_open_files(process_limits: &str) -> Result<u64, SnapshotError> {
    for line in process_limits.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some("Max")
            && fields.next() == Some("open")
            && fields.next() == Some("files")
        {
            let value = fields.next().ok_or(SnapshotError::Invalid)?;
            return if value == "unlimited" {
                Ok(u64::MAX)
            } else {
                value.parse::<u64>().map_err(|_| SnapshotError::Invalid)
            };
        }
    }
    Err(SnapshotError::Invalid)
}

#[cfg(target_os = "linux")]
fn process_start_time_seconds() -> Option<f64> {
    linux_process_start_time_seconds()
}

#[cfg(target_os = "linux")]
fn linux_process_start_time_seconds() -> Option<f64> {
    let process_stat = read_bounded_utf8(Path::new("/proc/self/stat")).ok()?;
    let system_stat = read_bounded_utf8(Path::new("/proc/stat")).ok()?;
    parse_linux_process_start_time(
        &process_stat,
        &system_stat,
        rustix::param::clock_ticks_per_second(),
    )
}

#[cfg(target_os = "macos")]
fn process_start_time_seconds() -> Option<f64> {
    let process = processkit::process_info(std::process::id()).ok()??;
    let start_time_micros = process.start_time()?;
    Some(Duration::from_micros(start_time_micros).as_secs_f64())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_start_time_seconds() -> Option<f64> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_process_start_time(
    process_stat: &str,
    system_stat: &str,
    clock_ticks_per_second: u64,
) -> Option<f64> {
    if clock_ticks_per_second == 0 {
        return None;
    }

    let fields = linux_stat_fields(process_stat).ok()?;
    let process_start_ticks = parse_stat_u64(&fields, 19).ok()?;
    let boot_time_seconds = system_stat
        .lines()
        .find_map(|line| line.strip_prefix("btime ")?.trim().parse::<u64>().ok())?;

    let whole_uptime_seconds = process_start_ticks / clock_ticks_per_second;
    let remaining_ticks = process_start_ticks % clock_ticks_per_second;
    let uptime_nanoseconds = remaining_ticks
        .checked_mul(1_000_000_000)?
        .checked_div(clock_ticks_per_second)?;
    let seconds = boot_time_seconds.checked_add(whole_uptime_seconds)?;
    let nanoseconds = u32::try_from(uptime_nanoseconds).ok()?;
    Some(Duration::new(seconds, nanoseconds).as_secs_f64())
}

fn register_process_start_time(root_registry: &mut Registry) {
    if let Some(timestamp) = process_start_time_seconds() {
        let metric = FloatGauge::default();
        metric.set(timestamp);
        root_registry.register_with_unit(
            "process_start_time",
            "Unix timestamp when this process started",
            Unit::Seconds,
            metric,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Mutex, atomic::AtomicUsize},
    };

    use prometheus_client::encoding::text::encode;

    use super::*;

    fn stat_fixture() -> String {
        let mut fields = vec!["0"; 22];
        fields[0] = "S";
        fields[11] = "125";
        fields[12] = "75";
        fields[17] = "7";
        fields[19] = "250";
        fields[20] = "4096";
        fields[21] = "3";
        format!("123 (worker ) nested (name)) {}", fields.join(" "))
    }

    fn snapshot(cpu_seconds: f64) -> ProcessSnapshot {
        ProcessSnapshot {
            cpu_seconds,
            resident_memory_bytes: 12_288,
            virtual_memory_bytes: 4_096,
            threads: 7,
            open_fds: 11,
            max_fds: 1_024,
        }
    }

    #[test]
    fn parses_linux_stat_with_nested_parentheses_and_resource_fields() {
        let parsed = parse_linux_process_snapshot(
            &stat_fixture(),
            "Limit Soft Limit Hard Limit Units\nMax open files 1024 4096 files\n",
            11,
            100,
            4_096,
        )
        .expect("valid bounded proc snapshot");
        assert_eq!(parsed, snapshot(2.0));

        let timestamp =
            parse_linux_process_start_time(&stat_fixture(), "cpu 1 2 3\nbtime 1000\n", 100)
                .expect("valid process start time");
        assert!((timestamp - 1002.5).abs() < f64::EPSILON);
    }

    #[test]
    fn parser_rejects_truncation_overflow_negative_and_malformed_limits() {
        let fixture = stat_fixture();
        let negative_rss = format!(
            "{}-1",
            fixture
                .strip_suffix('3')
                .expect("fixture has a resident-page field")
        );
        for stat in [
            "1 (name) S 1 2",
            &fixture.replacen("125", "18446744073709551615", 1),
            &negative_rss,
        ] {
            assert!(
                parse_linux_process_snapshot(
                    stat,
                    "Max open files 1024 1024 files\n",
                    1,
                    100,
                    4_096,
                )
                .is_err()
            );
        }
        assert!(
            parse_linux_process_snapshot(
                &stat_fixture(),
                "Max open files invalid invalid files\n",
                1,
                100,
                4_096,
            )
            .is_err()
        );
    }

    #[test]
    fn unlimited_open_file_limit_matches_linux_procfs_semantics() {
        let parsed = parse_linux_process_snapshot(
            &stat_fixture(),
            "Max open files unlimited unlimited files\n",
            11,
            100,
            4_096,
        )
        .expect("unlimited is a valid Linux soft limit");
        assert_eq!(parsed.max_fds, u64::MAX);
    }

    #[derive(Debug)]
    struct SequenceSource(Mutex<VecDeque<Result<ProcessSnapshot, SnapshotError>>>);

    impl ProcessSnapshotSource for SequenceSource {
        fn read(&self) -> Result<ProcessSnapshot, SnapshotError> {
            self.0
                .lock()
                .expect("sequence lock")
                .pop_front()
                .expect("a queued sample")
        }
    }

    #[test]
    fn failed_refresh_retains_last_good_values_and_marks_health() {
        let source = Arc::new(SequenceSource(Mutex::new(VecDeque::from([
            Ok(snapshot(2.0)),
            Err(SnapshotError::Unavailable),
            Ok(snapshot(1.0)),
        ]))));
        let mut registry = Registry::default();
        let sampler = ProcessMetricsSampler::register_with_source(&mut registry, source);

        sampler.refresh_at(UNIX_EPOCH + Duration::from_secs(10));
        sampler.refresh_at(UNIX_EPOCH + Duration::from_secs(20));
        sampler.refresh_at(UNIX_EPOCH + Duration::from_secs(30));

        assert!((sampler.metrics.cpu_seconds.get() - 2.0).abs() < f64::EPSILON);
        assert_eq!(sampler.metrics.resident_memory_bytes.get(), 12_288);
        assert_eq!(sampler.healthy.get(), 0);
        assert!((sampler.last_success_timestamp.get() - 10.0).abs() < f64::EPSILON);
        assert_eq!(
            sampler
                .refreshes
                .get_or_create(&RefreshLabels {
                    outcome: RefreshOutcome::Success,
                })
                .get(),
            1
        );
        assert_eq!(
            sampler
                .refreshes
                .get_or_create(&RefreshLabels {
                    outcome: RefreshOutcome::Error,
                })
                .get(),
            2
        );
    }

    #[test]
    fn exposition_uses_standard_unprefixed_names_and_closed_health_labels() {
        let source = Arc::new(SequenceSource(Mutex::new(VecDeque::from([Ok(snapshot(
            2.0,
        ))]))));
        let mut registry = Registry::default();
        let sampler = ProcessMetricsSampler::register_with_source(&mut registry, source);
        sampler.refresh_at(UNIX_EPOCH + Duration::from_secs(10));

        let mut exposition = String::new();
        encode(&mut exposition, &registry).expect("encode process registry");
        for name in [
            "process_cpu_seconds_total",
            "process_resident_memory_bytes",
            "process_virtual_memory_bytes",
            "process_threads",
            "process_open_fds",
            "process_max_fds",
            "automata_ci_metrics_process_snapshot_healthy",
            "automata_ci_metrics_process_snapshot_last_success_timestamp_seconds",
        ] {
            assert!(exposition.contains(name), "missing {name}: {exposition}");
        }
        assert!(exposition.contains(
            "automata_ci_metrics_process_snapshot_refreshes_total{outcome=\"success\"} 1"
        ));
        assert!(
            exposition.contains(
                "automata_ci_metrics_process_snapshot_refreshes_total{outcome=\"error\"} 0"
            )
        );
        assert!(!exposition.contains("automata_ci_process_cpu"));
    }

    #[derive(Debug)]
    struct CountingSource(AtomicUsize);

    impl ProcessSnapshotSource for CountingSource {
        fn read(&self) -> Result<ProcessSnapshot, SnapshotError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(snapshot(1.0))
        }
    }

    #[tokio::test]
    async fn cancellation_wins_before_a_scheduled_refresh() {
        let source = Arc::new(CountingSource(AtomicUsize::new(0)));
        let mut registry = Registry::default();
        let sampler = ProcessMetricsSampler::register_with_source(
            &mut registry,
            Arc::clone(&source) as Arc<dyn ProcessSnapshotSource>,
        );

        sampler
            .run_until_cancelled_with_interval(std::future::ready(()), Duration::from_secs(3_601))
            .await;
        assert_eq!(source.0.load(Ordering::Relaxed), 0);
    }
}
