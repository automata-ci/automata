#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_core::{
    Architecture, AttemptId, EnvironmentProfile, EnvironmentProfileId, FencingToken,
    IsolationLevel, JobAuthorityProfile, JobConclusion, JobId, JobInstanceIdentity, JobIr,
    JobIrEnvelope, JobLifecycle, JobPermissionRequest, JobResult, JobSecretExposure, JobSource,
    Lease, LeaseId, LogAck, LogChannel, LogFrame, OperationId, RunId, RunValueTemplates,
    RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements, RuntimeBoolean,
    SandboxCapabilities, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr, UnixMillis,
    ValueTemplate, WorkflowId,
};
use automata_ci_execution::{
    ExecutionArgv, ExecutionEnvironment, ImmutableImage, SandboxEnvironment, TargetPath,
};
use automata_ci_protocol::{
    CancelJob, CommandCursor, CommandSequence, ErrorMessage, HandshakeErrorCode, HandshakeRejected,
    JobResultMessage, JobRuntimeAuthorities, JobRuntimeAuthority, LeaseOffer, LeaseRenewal,
    LogAckMessage, MessageHeader, NegotiatedSession, NoWork, OperationAck, RemoteErrorCode,
    RunnerSlotOrdinal, RunnerToServer, RuntimeAuthorityCredential, RuntimeAuthorityEndpoint,
    RuntimeAuthorityName, SUPPORTED_PROTOCOL_RANGE, ServerCommandHeader, ServerHello, ServerTiming,
    ServerToRunner, SessionDisposition,
};
use automata_ci_protocol_protobuf::{encode_job_ir, encode_runtime_authorities};
use automata_ci_runner_journal::{
    DurableCommand, FileJournal, JobIrContentRef, LeaseOfferRecord, ProviderFailureKind,
    ProviderFailureOutcome, ProviderName, ProviderOperationKind, RunnerJournal,
    RuntimeAuthorityContentRef, SandboxHandle as JournalSandboxHandle, SandboxIdentity,
    SessionBinding, StateRoot, TerminalResultRecord,
};
use automata_ci_runner_runtime::{
    AdmissionRejection, CleanupFuture, CleanupRequest, ExecutionAdmission, ExecutionCancellation,
    ExecutionCancellationReason, ExecutionEvents, ExecutionRequest, ExecutorError,
    ExecutorErrorKind, ExecutorFuture, JobExecutor, LogEvent, MonotonicMillis, RetryPolicy,
    RunnerRuntimeConfig, RunnerRuntimeControlClient, RunnerRuntimeLimits, RuntimeClock,
    RuntimeControlError, RuntimeControlErrorKind, RuntimeControlFuture, RuntimeControlReply,
    RuntimeControlRetry, RuntimeSleeper, SleepFuture,
};
use automata_ci_runner_spool::{
    ContentKind, ContentProtectionError, ContentProtector, DurableContentPublication,
    DurableContentRef, DurableContentStore, FileSpool, ProtectionId, RetainedContentError,
    RetainedContentSource, SpoolError, SpoolRoot,
};
use automata_ci_runner_transport::PreparedRequest;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Deadlock guard for event-driven asynchronous tests.
pub const TEST_WATCHDOG: Duration = Duration::from_secs(15);

pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/agent-scratch/runner-runtime-tests")
            .join(format!("{label}-{}", OperationId::new()));
        fs::create_dir_all(&path).expect("create repository-local test scratch");
        Self {
            path: fs::canonicalize(path).expect("canonical test scratch"),
        }
    }

    pub fn journal_root(&self) -> StateRoot {
        StateRoot::explicit(self.path.join("journal")).expect("valid journal root")
    }

    pub fn spool_root(&self) -> SpoolRoot {
        SpoolRoot::explicit(self.path.join("spool")).expect("valid spool root")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct TestProtector {
    id: ProtectionId,
    key: [u8; 32],
}

/// Real file spool with deterministic one-shot capacity faults around the
/// terminal-result and subsequent runtime-owned EOS publications.
///
/// The phase only advances after the delegated retry has durably persisted its
/// bytes. Tests can therefore prove both publications reconciled before their
/// exact retry instead of merely observing a blind second call.
#[derive(Debug)]
pub struct TerminalCapacityProbeSpool {
    inner: FileSpool,
    phase: AtomicUsize,
    terminal_reconciliations: AtomicUsize,
    eos_reconciliations: AtomicUsize,
}

/// Simulates a completely full spool from sealed-head load until that exact
/// head is removed. Any ACK implementation that tries to publish replacement
/// bytes fails deterministically with capacity exhaustion.
#[derive(Debug)]
pub struct AckCapacitySpool {
    inner: FileSpool,
    ack_window: AtomicBool,
    persist_attempts_during_ack: AtomicUsize,
    reclaimed_heads: AtomicUsize,
}

impl AckCapacitySpool {
    pub fn new(inner: FileSpool) -> Self {
        Self {
            inner,
            ack_window: AtomicBool::new(false),
            persist_attempts_during_ack: AtomicUsize::new(0),
            reclaimed_heads: AtomicUsize::new(0),
        }
    }

    pub fn persist_attempts_during_ack(&self) -> usize {
        self.persist_attempts_during_ack.load(Ordering::SeqCst)
    }

    pub fn reclaimed_heads(&self) -> usize {
        self.reclaimed_heads.load(Ordering::SeqCst)
    }
}

impl DurableContentStore for AckCapacitySpool {
    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError> {
        if self.ack_window.load(Ordering::SeqCst) {
            self.persist_attempts_during_ack
                .fetch_add(1, Ordering::SeqCst);
            return Err(SpoolError::CapacityExhausted);
        }
        self.inner.persist(kind, plaintext)
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError> {
        let bytes = self.inner.load(reference)?;
        if reference.kind() == ContentKind::LogSpool {
            self.ack_window.store(true, Ordering::SeqCst);
        }
        Ok(bytes)
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError> {
        let removed = self.inner.remove(reference)?;
        if reference.kind() == ContentKind::LogSpool {
            self.ack_window.store(false, Ordering::SeqCst);
            self.reclaimed_heads.fetch_add(1, Ordering::SeqCst);
        }
        Ok(removed)
    }

    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError> {
        self.inner.reconcile(retained)
    }
}

impl TerminalCapacityProbeSpool {
    pub fn new(inner: FileSpool) -> Self {
        Self {
            inner,
            phase: AtomicUsize::new(0),
            terminal_reconciliations: AtomicUsize::new(0),
            eos_reconciliations: AtomicUsize::new(0),
        }
    }

    pub fn terminal_reconciliations(&self) -> usize {
        self.terminal_reconciliations.load(Ordering::SeqCst)
    }

    pub fn eos_reconciliations(&self) -> usize {
        self.eos_reconciliations.load(Ordering::SeqCst)
    }

    pub fn completed_fault_cycle(&self) -> bool {
        self.phase.load(Ordering::SeqCst) == 4
    }
}

impl DurableContentStore for TerminalCapacityProbeSpool {
    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError> {
        if kind == ContentKind::TerminalResult
            && self
                .phase
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Err(SpoolError::CapacityExhausted);
        }
        if kind == ContentKind::LogSpool
            && self
                .phase
                .compare_exchange(2, 3, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Err(SpoolError::CapacityExhausted);
        }

        let publication = self.inner.persist(kind, plaintext)?;
        if kind == ContentKind::TerminalResult {
            let _ = self
                .phase
                .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst);
        } else if kind == ContentKind::LogSpool {
            let _ = self
                .phase
                .compare_exchange(3, 4, Ordering::SeqCst, Ordering::SeqCst);
        }
        Ok(publication)
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError> {
        self.inner.load(reference)
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError> {
        self.inner.remove(reference)
    }

    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError> {
        self.inner.reconcile(retained)?;
        match self.phase.load(Ordering::SeqCst) {
            1 => {
                self.terminal_reconciliations.fetch_add(1, Ordering::SeqCst);
            }
            3 => {
                self.eos_reconciliations.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Injects capacity exhaustion while a nested `JobIR` publication is holding its
/// payload-first fence and the runtime attempts to persist its authority pair.
#[derive(Debug)]
pub struct NestedOfferCapacityProbeSpool {
    inner: FileSpool,
    phase: AtomicUsize,
    reconciliations: AtomicUsize,
}

impl NestedOfferCapacityProbeSpool {
    pub fn new(inner: FileSpool) -> Self {
        Self {
            inner,
            phase: AtomicUsize::new(0),
            reconciliations: AtomicUsize::new(0),
        }
    }

    pub fn completed_fault_cycle(&self) -> bool {
        self.phase.load(Ordering::SeqCst) == 2
    }

    pub fn reconciliations(&self) -> usize {
        self.reconciliations.load(Ordering::SeqCst)
    }
}

impl DurableContentStore for NestedOfferCapacityProbeSpool {
    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError> {
        if kind == ContentKind::RuntimeAuthority
            && self
                .phase
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Err(SpoolError::CapacityExhausted);
        }
        let publication = self.inner.persist(kind, plaintext)?;
        if kind == ContentKind::RuntimeAuthority {
            let _ = self
                .phase
                .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst);
        }
        Ok(publication)
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError> {
        self.inner.load(reference)
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError> {
        self.inner.remove(reference)
    }

    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError> {
        self.inner.reconcile(retained)?;
        if self.phase.load(Ordering::SeqCst) == 1 {
            self.reconciliations.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct BlockingEosState {
    entered: bool,
    released: bool,
}

/// Holds the first non-empty log-segment publication until a test releases
/// it, exercising heartbeats while runtime-owned EOS work is in `spawn_blocking`.
#[derive(Debug)]
pub struct BlockingEosSpool {
    inner: FileSpool,
    state: Mutex<BlockingEosState>,
    release: Condvar,
    changed: tokio::sync::Notify,
}

impl BlockingEosSpool {
    pub fn new(inner: FileSpool) -> Self {
        Self {
            inner,
            state: Mutex::new(BlockingEosState::default()),
            release: Condvar::new(),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub async fn wait_for_eos_publication(&self) {
        loop {
            let changed = self.changed.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entered
            {
                return;
            }
            changed.await;
        }
    }

    pub fn release_eos_publication(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.released = true;
        self.release.notify_all();
    }
}

impl DurableContentStore for BlockingEosSpool {
    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError> {
        if kind == ContentKind::LogSpool && !plaintext.is_empty() {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if !state.entered {
                state.entered = true;
                self.changed.notify_waiters();
                while !state.released {
                    let (next, timeout) = self
                        .release
                        .wait_timeout(state, Duration::from_secs(5))
                        .unwrap_or_else(PoisonError::into_inner);
                    state = next;
                    if timeout.timed_out() {
                        state.released = true;
                    }
                }
            }
        }
        self.inner.persist(kind, plaintext)
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError> {
        self.inner.load(reference)
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError> {
        self.inner.remove(reference)
    }

    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError> {
        self.inner.reconcile(retained)
    }
}

#[derive(Debug, Default)]
struct BlockingSegmentLoadState {
    armed: bool,
    entered: bool,
    released: bool,
}

/// Blocks one sealed log-head load after its bytes are copied. The runtime's
/// coordinator must keep tail publication and reconciliation outside the
/// snapshot/load fence until the copied head is released.
#[derive(Debug)]
pub struct BlockingSegmentLoadSpool {
    inner: Arc<FileSpool>,
    state: Mutex<BlockingSegmentLoadState>,
    release: Condvar,
    changed: tokio::sync::Notify,
}

impl BlockingSegmentLoadSpool {
    pub fn new(inner: Arc<FileSpool>) -> Self {
        Self {
            inner,
            state: Mutex::new(BlockingSegmentLoadState::default()),
            release: Condvar::new(),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub fn arm_next_log_load(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(!state.armed && !state.entered, "load fence arms once");
        state.armed = true;
    }

    pub async fn wait_for_blocked_load(&self) {
        loop {
            let changed = self.changed.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entered
            {
                return;
            }
            changed.await;
        }
    }

    pub fn release_blocked_load(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(state.entered, "load entered before release");
        state.released = true;
        self.release.notify_all();
    }
}

impl DurableContentStore for BlockingSegmentLoadSpool {
    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError> {
        self.inner.persist(kind, plaintext)
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError> {
        let bytes = self.inner.load(reference)?;
        if reference.kind() == ContentKind::LogSpool {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.armed {
                state.armed = false;
                state.entered = true;
                self.changed.notify_waiters();
                while !state.released {
                    let (next, timeout) = self
                        .release
                        .wait_timeout(state, Duration::from_secs(5))
                        .unwrap_or_else(PoisonError::into_inner);
                    state = next;
                    assert!(
                        !timeout.timed_out(),
                        "blocked segment load was not released"
                    );
                }
            }
        }
        Ok(bytes)
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError> {
        self.inner.remove(reference)
    }

    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError> {
        self.inner.reconcile(retained)
    }
}

impl TestProtector {
    pub fn new() -> Self {
        Self {
            id: ProtectionId::new("runtime-test-protection-v1").expect("protection ID"),
            key: [0x6d; 32],
        }
    }

    fn tag(&self, reference: &DurableContentRef, ciphertext: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.key);
        digest.update(reference.cache_key().as_str().as_bytes());
        digest.update(ciphertext);
        digest.finalize().into()
    }
}

impl fmt::Debug for TestProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestProtector")
            .field("id", &self.id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ContentProtector for TestProtector {
    fn protection_id(&self) -> &ProtectionId {
        &self.id
    }

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        let mut protected = Vec::with_capacity(plaintext.len() + 32);
        protected.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ self.key[index % self.key.len()]),
        );
        protected.extend_from_slice(&self.tag(reference, &protected));
        Ok(protected)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        if protected.len() < 32 {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        let tag_offset = protected.len() - 32;
        let ciphertext = &protected[..tag_offset];
        if protected[tag_offset..] != self.tag(reference, ciphertext) {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        Ok(ciphertext
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ self.key[index % self.key.len()])
            .collect())
    }
}

pub fn environment() -> EnvironmentProfile {
    EnvironmentProfile::new(
        EnvironmentProfileId::new("github.com/ubuntu-24.04").expect("profile ID"),
        Sha256Digest::from_bytes([0xa5; 32]),
    )
}

pub fn sandbox_environment() -> SandboxEnvironment {
    sandbox_environment_for(environment())
}

fn sandbox_environment_for(attestation: EnvironmentProfile) -> SandboxEnvironment {
    SandboxEnvironment::new(
        attestation,
        ImmutableImage::new(format!(
            "ghcr.io/automata-ci/automata-runner@sha256:{}",
            "a5".repeat(32)
        ))
        .expect("immutable image"),
        ExecutionArgv::new(
            TargetPath::posix("/usr/bin/sleep").expect("keepalive path"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive argv"),
        TargetPath::posix("/__w").expect("workspace path"),
        ExecutionEnvironment::empty(),
    )
    .expect("sandbox environment")
}

pub fn capabilities(runner_id: RunnerId, slots: u16) -> RunnerCapabilities {
    RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(
            automata_ci_core::OperatingSystem::Linux,
            Architecture::X86_64,
        ),
    )
    .with_max_parallel_jobs(slots)
    .expect("positive slots")
    .with_sandbox(SandboxCapabilities::new(IsolationLevel::SharedKernel, []))
    .with_environment_profiles([environment()])
}

pub fn durable_ports(scratch: &Scratch, runner_id: RunnerId) -> (Arc<FileJournal>, Arc<FileSpool>) {
    let journal = Arc::new(
        FileJournal::open(scratch.journal_root(), runner_id).expect("open runtime journal"),
    );
    let spool = Arc::new(
        FileSpool::open(scratch.spool_root(), Arc::new(TestProtector::new()))
            .expect("open runtime spool"),
    );
    (journal, spool)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentRaceMode {
    PublicationFirst,
    ReconciliationFirst,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PublicationRaceStage {
    #[default]
    Idle,
    Claimed,
    Entered,
    Released,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ReconciliationRaceStage {
    #[default]
    Idle,
    Armed,
    Claimed,
    Entered,
    Released,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum LogRaceStage {
    #[default]
    Idle,
    Attempted,
    Finished,
}

#[derive(Debug, Default)]
struct ContentRaceState {
    publication: PublicationRaceStage,
    reconciliation: ReconciliationRaceStage,
    log: LogRaceStage,
    persist_entered_during_reconciliation: bool,
}

#[derive(Debug)]
struct ContentRaceSignals {
    mode: ContentRaceMode,
    state: Mutex<ContentRaceState>,
    release: Condvar,
    changed: tokio::sync::Notify,
}

#[derive(Clone, Debug)]
pub struct ContentRaceProbe {
    signals: Arc<ContentRaceSignals>,
}

impl ContentRaceProbe {
    pub fn new(mode: ContentRaceMode) -> Self {
        Self {
            signals: Arc::new(ContentRaceSignals {
                mode,
                state: Mutex::new(ContentRaceState::default()),
                release: Condvar::new(),
                changed: tokio::sync::Notify::new(),
            }),
        }
    }

    pub fn mode(&self) -> ContentRaceMode {
        self.signals.mode
    }

    pub fn cancellation_may_be_sent(&self) -> bool {
        let state = self
            .signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.mode() == ContentRaceMode::ReconciliationFirst
            || state.publication == PublicationRaceStage::Entered
    }

    pub fn arm_reconciliation(&self) {
        self.signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reconciliation = ReconciliationRaceStage::Armed;
    }

    pub fn mark_log_attempt_started(&self) {
        self.signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .log = LogRaceStage::Attempted;
        self.signals.changed.notify_waiters();
    }

    pub fn mark_log_publication_finished(&self) {
        self.signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .log = LogRaceStage::Finished;
        self.signals.changed.notify_waiters();
    }

    pub fn release_publication(&self) {
        self.signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .publication = PublicationRaceStage::Released;
        self.signals.release.notify_all();
        self.signals.changed.notify_waiters();
    }

    pub fn release_reconciliation(&self) {
        self.signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reconciliation = ReconciliationRaceStage::Released;
        self.signals.release.notify_all();
        self.signals.changed.notify_waiters();
    }

    pub fn persist_entered_during_reconciliation(&self) -> bool {
        self.signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .persist_entered_during_reconciliation
    }

    pub fn wait_for_reconciliation_blocking(&self) {
        let mut state = self
            .signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while !matches!(
            state.reconciliation,
            ReconciliationRaceStage::Entered | ReconciliationRaceStage::Released
        ) {
            let (next, timeout) = self
                .signals
                .release
                .wait_timeout(state, Duration::from_secs(5))
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            if timeout.timed_out() {
                return;
            }
        }
    }

    pub async fn wait_for_publication(&self) {
        self.wait_until(|state| state.publication == PublicationRaceStage::Entered)
            .await;
    }

    pub async fn wait_for_reconciliation(&self) {
        self.wait_until(|state| state.reconciliation == ReconciliationRaceStage::Entered)
            .await;
    }

    pub async fn wait_for_log_attempt(&self) {
        self.wait_until(|state| state.log == LogRaceStage::Attempted)
            .await;
    }

    pub async fn wait_for_log_publication_finished(&self) {
        self.wait_until(|state| state.log == LogRaceStage::Finished)
            .await;
    }

    async fn wait_until(&self, predicate: impl Fn(&ContentRaceState) -> bool) {
        loop {
            let changed = self.signals.changed.notified();
            if predicate(
                &self
                    .signals
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner),
            ) {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Debug)]
pub struct ContentRaceSpool {
    inner: Arc<FileSpool>,
    probe: ContentRaceProbe,
}

impl ContentRaceSpool {
    pub fn new(inner: Arc<FileSpool>, probe: ContentRaceProbe) -> Self {
        Self { inner, probe }
    }
}

impl DurableContentStore for ContentRaceSpool {
    fn persist(
        &self,
        kind: ContentKind,
        plaintext: &[u8],
    ) -> Result<DurableContentPublication<'_>, SpoolError> {
        {
            let mut state = self
                .probe
                .signals
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if state.reconciliation == ReconciliationRaceStage::Entered {
                state.persist_entered_during_reconciliation = true;
                self.probe.signals.changed.notify_waiters();
            }
        }
        let block = {
            let mut state = self
                .probe
                .signals
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let block = self.probe.mode() == ContentRaceMode::PublicationFirst
                && kind == ContentKind::LogSpool
                && !plaintext.is_empty()
                && state.publication == PublicationRaceStage::Idle;
            if block {
                state.publication = PublicationRaceStage::Claimed;
            }
            block
        };
        let publication = self.inner.persist(kind, plaintext)?;
        if block {
            let mut state = self
                .probe
                .signals
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.publication = PublicationRaceStage::Entered;
            self.probe.signals.changed.notify_waiters();
            while state.publication != PublicationRaceStage::Released {
                let (next, timeout) = self
                    .probe
                    .signals
                    .release
                    .wait_timeout(state, Duration::from_secs(5))
                    .unwrap_or_else(PoisonError::into_inner);
                state = next;
                if timeout.timed_out() {
                    state.publication = PublicationRaceStage::Released;
                }
            }
        }
        Ok(publication)
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, SpoolError> {
        self.inner.load(reference)
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, SpoolError> {
        self.inner.remove(reference)
    }

    fn reconcile(&self, retained: &dyn RetainedContentSource) -> Result<(), SpoolError> {
        let block = {
            let mut state = self
                .probe
                .signals
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let block = self.probe.mode() == ContentRaceMode::ReconciliationFirst
                && state.reconciliation == ReconciliationRaceStage::Armed;
            if block {
                state.reconciliation = ReconciliationRaceStage::Claimed;
            }
            block
        };
        if block {
            self.inner.reconcile(&BlockingRetainSet {
                inner: retained,
                probe: &self.probe,
            })
        } else {
            self.inner.reconcile(retained)
        }
    }
}

struct BlockingRetainSet<'a> {
    inner: &'a dyn RetainedContentSource,
    probe: &'a ContentRaceProbe,
}

impl RetainedContentSource for BlockingRetainSet<'_> {
    fn retained_content(&self) -> Result<Vec<DurableContentRef>, RetainedContentError> {
        let retained = self.inner.retained_content()?;
        let mut state = self
            .probe
            .signals
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.reconciliation = ReconciliationRaceStage::Entered;
        self.probe.signals.changed.notify_waiters();
        self.probe.signals.release.notify_all();
        while state.reconciliation != ReconciliationRaceStage::Released {
            let (next, timeout) = self
                .probe
                .signals
                .release
                .wait_timeout(state, Duration::from_secs(5))
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            if timeout.timed_out() {
                state.reconciliation = ReconciliationRaceStage::Released;
            }
        }
        Ok(retained)
    }
}

#[derive(Debug)]
pub struct FixedClock {
    wall: i64,
    monotonic: u64,
}

impl FixedClock {
    pub const fn new(wall: i64, monotonic: u64) -> Self {
        Self { wall, monotonic }
    }
}

impl RuntimeClock for FixedClock {
    fn wall_now(&self) -> UnixMillis {
        UnixMillis::new(self.wall)
    }

    fn monotonic_now(&self) -> MonotonicMillis {
        MonotonicMillis::new(self.monotonic)
    }
}

#[derive(Debug)]
pub struct ManualClock {
    wall: i64,
    monotonic: AtomicU64,
}

impl ManualClock {
    pub const fn new(wall: i64, monotonic: u64) -> Self {
        Self {
            wall,
            monotonic: AtomicU64::new(monotonic),
        }
    }

    pub fn set_monotonic(&self, monotonic: u64) {
        self.monotonic.store(monotonic, Ordering::SeqCst);
    }

    pub fn advance_monotonic(&self, millis: u64) -> u64 {
        self.monotonic
            .fetch_add(millis, Ordering::SeqCst)
            .saturating_add(millis)
    }
}

impl RuntimeClock for ManualClock {
    fn wall_now(&self) -> UnixMillis {
        UnixMillis::new(self.wall)
    }

    fn monotonic_now(&self) -> MonotonicMillis {
        MonotonicMillis::new(self.monotonic.load(Ordering::SeqCst))
    }
}

#[derive(Debug)]
pub struct ManualDeadlineSleeper {
    clock: Arc<ManualClock>,
    changed: tokio::sync::Notify,
}

impl ManualDeadlineSleeper {
    pub fn new(clock: Arc<ManualClock>) -> Self {
        Self {
            clock,
            changed: tokio::sync::Notify::new(),
        }
    }

    pub fn advance(&self, millis: u64) -> u64 {
        let now = self.clock.advance_monotonic(millis);
        self.changed.notify_waiters();
        now
    }

    pub fn monotonic_now(&self) -> MonotonicMillis {
        self.clock.monotonic_now()
    }
}

impl RuntimeSleeper for ManualDeadlineSleeper {
    fn sleep(&self, duration: Duration, cancellation: CancellationToken) -> SleepFuture<'_> {
        let deadline = self.clock.monotonic_now().saturating_add(duration);
        Box::pin(async move {
            loop {
                let changed = self.changed.notified();
                if cancellation.is_cancelled() || self.clock.monotonic_now() >= deadline {
                    return;
                }
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return,
                    () = changed => {}
                }
            }
        })
    }
}

#[derive(Debug)]
pub struct ImmediateSleeper;

impl RuntimeSleeper for ImmediateSleeper {
    fn sleep(&self, _duration: Duration, _cancellation: CancellationToken) -> SleepFuture<'_> {
        Box::pin(async { tokio::task::yield_now().await })
    }
}

#[derive(Debug, Default)]
pub struct CancellationAwareSleeper {
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
}

impl CancellationAwareSleeper {
    pub async fn wait_until_entered(&self) {
        self.entered.notified().await;
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl RuntimeSleeper for CancellationAwareSleeper {
    fn sleep(&self, _duration: Duration, cancellation: CancellationToken) -> SleepFuture<'_> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            cancellation.cancelled().await;
        })
    }
}

#[derive(Debug, Default)]
pub struct CommandGapSleeper {
    calls: AtomicUsize,
    changed: tokio::sync::Notify,
}

impl CommandGapSleeper {
    pub async fn wait_for_calls(&self, minimum: usize, cancellation: &CancellationToken) -> bool {
        loop {
            let changed = self.changed.notified();
            if self.calls.load(Ordering::SeqCst) >= minimum {
                return true;
            }
            tokio::select! {
                () = changed => {}
                () = cancellation.cancelled() => return false,
            }
        }
    }
}

impl RuntimeSleeper for CommandGapSleeper {
    fn sleep(&self, _duration: Duration, cancellation: CancellationToken) -> SleepFuture<'_> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
            tokio::select! {
                () = tokio::task::yield_now() => {}
                () = cancellation.cancelled() => {}
            }
        })
    }
}

#[derive(Debug)]
pub struct NeverExecutor;

impl JobExecutor for NeverExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Err(AdmissionRejection::InvalidJob)
    }

    fn execute(
        &self,
        _request: ExecutionRequest,
        _events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Err(ExecutorError::new(ExecutorErrorKind::Internal)) })
    }
}

#[derive(Debug)]
pub struct AdmittingExecutor;

impl JobExecutor for AdmittingExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        _request: ExecutionRequest,
        _events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug, Default)]
pub struct AckProgressExecutor {
    started_slots: AtomicUsize,
}

impl AckProgressExecutor {
    pub fn started_slots(&self) -> usize {
        self.started_slots.load(Ordering::SeqCst)
    }
}

impl JobExecutor for AckProgressExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            let bit = usize::from(request.slot().get())
                .checked_sub(1)
                .and_then(|shift| 1_usize.checked_shl(u32::try_from(shift).ok()?))
                .ok_or_else(|| ExecutorError::new(ExecutorErrorKind::Internal))?;
            self.started_slots.fetch_or(bit, Ordering::SeqCst);
            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
pub struct CancellationExecutor {
    running: Arc<AtomicBool>,
    observed_reason: Mutex<Option<ExecutionCancellationReason>>,
}

impl CancellationExecutor {
    pub fn new(running: Arc<AtomicBool>) -> Self {
        Self {
            running,
            observed_reason: Mutex::new(None),
        }
    }

    pub fn observed_reason(&self) -> Option<ExecutionCancellationReason> {
        *self
            .observed_reason
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl JobExecutor for CancellationExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            self.running.store(true, Ordering::SeqCst);
            cancellation.token().cancelled().await;
            *self
                .observed_reason
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = cancellation.reason();
            Ok(JobResult::new(
                request.lease().attempt_id(),
                JobConclusion::Cancelled,
                JobSecretExposure::Secretless,
                UnixMillis::new(10_001),
            ))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
pub struct CancellationTimeoutExecutor {
    running: Arc<AtomicBool>,
    cancellation: Mutex<Option<ExecutionCancellation>>,
    execution_dropped: AtomicBool,
    cleanup_called: AtomicBool,
    cleanup_before_drop: AtomicBool,
}

impl CancellationTimeoutExecutor {
    pub fn new(running: Arc<AtomicBool>) -> Self {
        Self {
            running,
            cancellation: Mutex::new(None),
            execution_dropped: AtomicBool::new(false),
            cleanup_called: AtomicBool::new(false),
            cleanup_before_drop: AtomicBool::new(false),
        }
    }

    pub fn execution_dropped(&self) -> bool {
        self.execution_dropped.load(Ordering::SeqCst)
    }

    pub fn observed_reason(&self) -> Option<ExecutionCancellationReason> {
        self.cancellation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(ExecutionCancellation::reason)
    }

    pub fn cleanup_called(&self) -> bool {
        self.cleanup_called.load(Ordering::SeqCst)
    }

    pub fn cleanup_before_drop(&self) -> bool {
        self.cleanup_before_drop.load(Ordering::SeqCst)
    }
}

struct ExecutionDropProbe<'a>(&'a AtomicBool);

impl Drop for ExecutionDropProbe<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl JobExecutor for CancellationTimeoutExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        _request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            let create = events
                .begin_provider_operation(ProviderOperationKind::CreateSandbox)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            events
                .sandbox_created(
                    create,
                    SandboxIdentity::new(
                        ProviderName::new("cancellation-timeout-provider")
                            .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?,
                        JournalSandboxHandle::new("cancellation-timeout-sandbox")
                            .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?,
                    ),
                )
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            *self
                .cancellation
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(cancellation);
            self.running.store(true, Ordering::SeqCst);
            let _drop_probe = ExecutionDropProbe(&self.execution_dropped);
            std::future::pending::<()>().await;
            unreachable!("the cancellation-timeout executor is aborted")
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async move {
            self.cleanup_called.store(true, Ordering::SeqCst);
            if !self.execution_dropped.load(Ordering::SeqCst) {
                self.cleanup_before_drop.store(true, Ordering::SeqCst);
            }
            let destroy = events
                .begin_provider_operation(ProviderOperationKind::DestroySandbox)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            events
                .provider_operation_completed(destroy)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))
        })
    }
}

#[derive(Debug)]
pub struct CancellationContentRaceExecutor {
    probe: ContentRaceProbe,
    started_slots: AtomicUsize,
}

impl CancellationContentRaceExecutor {
    pub fn new(probe: ContentRaceProbe) -> Self {
        Self {
            probe,
            started_slots: AtomicUsize::new(0),
        }
    }

    pub fn cancellation_ready(&self) -> bool {
        self.started_slots.load(Ordering::SeqCst) == 0b11
    }
}

impl JobExecutor for CancellationContentRaceExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            self.started_slots.fetch_or(
                1_usize << usize::from(request.slot().get() - 1),
                Ordering::SeqCst,
            );
            if request.slot().get() == 1 {
                cancellation.token().cancelled().await;
                if self.probe.mode() == ContentRaceMode::ReconciliationFirst {
                    self.probe.arm_reconciliation();
                }
                return Err(ExecutorError::new(ExecutorErrorKind::Cancelled));
            }

            if self.probe.mode() == ContentRaceMode::ReconciliationFirst {
                let probe = self.probe.clone();
                tokio::task::spawn_blocking(move || probe.wait_for_reconciliation_blocking())
                    .await
                    .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            }
            self.probe.mark_log_attempt_started();
            events
                .emit_log(LogEvent::new(
                    LogChannel::Stdout,
                    b"sibling publication".to_vec(),
                ))
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            self.probe.mark_log_publication_finished();
            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug, Default)]
pub struct LegacyUncertainCreateExecutor {
    recovery_calls: Mutex<Vec<(OperationId, automata_ci_core::LeaseGuard)>>,
    cleanup_calls: AtomicUsize,
}

impl LegacyUncertainCreateExecutor {
    pub fn recovery_calls(&self) -> Vec<(OperationId, automata_ci_core::LeaseGuard)> {
        self.recovery_calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn cleanup_calls(&self) -> usize {
        self.cleanup_calls.load(Ordering::SeqCst)
    }

    fn recovery_identity() -> SandboxIdentity {
        SandboxIdentity::new(
            ProviderName::new("legacy-recovery-provider").expect("provider name"),
            JournalSandboxHandle::new("legacy-uncertain-create").expect("sandbox handle"),
        )
    }
}

impl JobExecutor for LegacyUncertainCreateExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn create_recovery_sandbox(
        &self,
        operation_id: OperationId,
        guard: automata_ci_core::LeaseGuard,
    ) -> Result<Option<SandboxIdentity>, ExecutorError> {
        self.recovery_calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((operation_id, guard));
        Ok(Some(Self::recovery_identity()))
    }

    fn execute(
        &self,
        _request: ExecutionRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async { Err(ExecutorError::new(ExecutorErrorKind::Internal)) })
    }

    fn cleanup(
        &self,
        request: CleanupRequest,
        events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async move {
            if request.sandbox() != &Self::recovery_identity() {
                return Err(ExecutorError::new(ExecutorErrorKind::Internal));
            }
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            let destroy = events
                .begin_provider_operation(ProviderOperationKind::DestroySandbox)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            events
                .provider_operation_completed(destroy)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))
        })
    }
}

#[derive(Debug, Default)]
pub struct FailureIsolationExecutor {
    survivor_started: AtomicBool,
}

pub const FAILURE_ISOLATION_LOG_COUNT: usize = 64;

impl FailureIsolationExecutor {
    pub fn survivor_started(&self) -> bool {
        self.survivor_started.load(Ordering::SeqCst)
    }
}

impl JobExecutor for FailureIsolationExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            if request.slot().get() == 1 {
                events
                    .transition(JobLifecycle::Running)
                    .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                for sequence in 0..FAILURE_ISOLATION_LOG_COUNT {
                    events
                        .emit_log(LogEvent::new(
                            LogChannel::Stdout,
                            format!("failed executor log {sequence}").into_bytes(),
                        ))
                        .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                }
                return Err(ExecutorError::new(ExecutorErrorKind::Internal));
            }
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            self.survivor_started.store(true, Ordering::SeqCst);
            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalCleanupStage {
    PayloadAcknowledged,
    EosAcknowledged,
    SandboxDestroyStarted,
    TerminalResultDelivered,
    ReleasedSlotPolled,
}

#[derive(Debug, Default)]
pub struct TerminalCleanupOrderProbe {
    stages: Mutex<Vec<TerminalCleanupStage>>,
}

impl TerminalCleanupOrderProbe {
    fn record(&self, stage: TerminalCleanupStage) {
        self.stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(stage);
    }

    pub fn stages(&self) -> Vec<TerminalCleanupStage> {
        self.stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[derive(Debug, Default)]
pub struct CleanupIsolationExecutor {
    survivor_started: AtomicBool,
    cleanup_attempts: AtomicUsize,
    cleanup_operations: Mutex<Vec<OperationId>>,
    cleanup_parked: tokio::sync::Notify,
    cleanup_release: (Mutex<bool>, Condvar),
    order_probe: Option<Arc<TerminalCleanupOrderProbe>>,
}

impl CleanupIsolationExecutor {
    pub fn with_order_probe(order_probe: Arc<TerminalCleanupOrderProbe>) -> Self {
        Self {
            order_probe: Some(order_probe),
            ..Self::default()
        }
    }

    pub fn survivor_started(&self) -> bool {
        self.survivor_started.load(Ordering::SeqCst)
    }

    pub fn cleanup_attempts(&self) -> usize {
        self.cleanup_attempts.load(Ordering::SeqCst)
    }

    pub fn cleanup_operations(&self) -> Vec<OperationId> {
        self.cleanup_operations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub async fn wait_until_cleanup_is_parked(&self) {
        loop {
            let changed = self.cleanup_parked.notified();
            if self.cleanup_attempts() >= 2 {
                return;
            }
            changed.await;
        }
    }

    pub fn release_cleanup(&self) {
        let (released, changed) = &self.cleanup_release;
        *released.lock().unwrap_or_else(PoisonError::into_inner) = true;
        changed.notify_all();
    }
}

impl JobExecutor for CleanupIsolationExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            if request.slot().get() == 1 {
                let create = events
                    .begin_provider_operation(ProviderOperationKind::CreateSandbox)
                    .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                events
                    .sandbox_created(
                        create,
                        SandboxIdentity::new(
                            ProviderName::new("cleanup-isolation-provider")
                                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?,
                            JournalSandboxHandle::new("cleanup-isolation-sandbox")
                                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?,
                        ),
                    )
                    .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                events
                    .transition(JobLifecycle::Running)
                    .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                if self.order_probe.is_some() {
                    events
                        .emit_log(LogEvent::new(
                            LogChannel::Stdout,
                            b"terminal cleanup ordering".to_vec(),
                        ))
                        .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                }
                return Ok(JobResult::new(
                    request.lease().attempt_id(),
                    JobConclusion::Failure,
                    JobSecretExposure::Secretless,
                    UnixMillis::new(10_001),
                ));
            }
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            self.survivor_started.store(true, Ordering::SeqCst);
            events
                .emit_log(LogEvent::new(
                    LogChannel::Stdout,
                    b"surviving execution".to_vec(),
                ))
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async move {
            if let Some(probe) = &self.order_probe {
                probe.record(TerminalCleanupStage::SandboxDestroyStarted);
            }
            let operation_id = events
                .begin_provider_operation(ProviderOperationKind::DestroySandbox)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            self.cleanup_operations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(operation_id);
            let attempt = self.cleanup_attempts.fetch_add(1, Ordering::SeqCst) + 1;
            self.cleanup_parked.notify_one();
            if attempt == 1 {
                events
                    .provider_operation_failed(
                        operation_id,
                        ProviderFailureOutcome::Uncertain(ProviderFailureKind::Unavailable),
                    )
                    .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                return Err(ExecutorError::new(ExecutorErrorKind::Unavailable));
            }
            let (released, changed) = &self.cleanup_release;
            let mut released = released.lock().unwrap_or_else(PoisonError::into_inner);
            while !*released {
                if cancellation.is_cancelled() {
                    return Err(ExecutorError::new(ExecutorErrorKind::Cancelled));
                }
                let (next, _) = changed
                    .wait_timeout(released, Duration::from_millis(10))
                    .unwrap_or_else(PoisonError::into_inner);
                released = next;
            }
            drop(released);
            events
                .provider_operation_completed(operation_id)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))
        })
    }
}

#[derive(Debug)]
pub struct BurstLogExecutor {
    data_frames: usize,
    conclusion: JobConclusion,
}

#[derive(Debug)]
pub struct CapacityFailureIsolationExecutor {
    data_frames: usize,
    payload_bytes: usize,
    survivor_started: AtomicBool,
}

impl CapacityFailureIsolationExecutor {
    pub const fn new(data_frames: usize, payload_bytes: usize) -> Self {
        Self {
            data_frames,
            payload_bytes,
            survivor_started: AtomicBool::new(false),
        }
    }

    pub fn survivor_started(&self) -> bool {
        self.survivor_started.load(Ordering::SeqCst)
    }
}

impl JobExecutor for CapacityFailureIsolationExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            if request.slot().get() == 1 {
                for _ in 0..self.data_frames {
                    events
                        .emit_log(LogEvent::new(
                            LogChannel::Stdout,
                            vec![b'x'; self.payload_bytes],
                        ))
                        .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                }
                return Err(ExecutorError::new(ExecutorErrorKind::Internal));
            }

            self.survivor_started.store(true, Ordering::SeqCst);
            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

impl BurstLogExecutor {
    pub const fn new(data_frames: usize) -> Self {
        Self {
            data_frames,
            conclusion: JobConclusion::Success,
        }
    }

    pub const fn with_conclusion(data_frames: usize, conclusion: JobConclusion) -> Self {
        Self {
            data_frames,
            conclusion,
        }
    }
}

#[derive(Debug)]
pub struct ActiveLogExecutor {
    data_frames: usize,
    emitted_slots: AtomicUsize,
    changed: tokio::sync::Notify,
}

impl ActiveLogExecutor {
    pub const fn new(data_frames: usize) -> Self {
        Self {
            data_frames,
            emitted_slots: AtomicUsize::new(0),
            changed: tokio::sync::Notify::const_new(),
        }
    }

    pub async fn wait_for_emitters(&self, minimum: usize) {
        loop {
            let changed = self.changed.notified();
            if self.emitted_slots.load(Ordering::SeqCst) >= minimum {
                return;
            }
            changed.await;
        }
    }
}

impl JobExecutor for ActiveLogExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        _request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            for index in 0..self.data_frames {
                events
                    .emit_log(LogEvent::new(
                        LogChannel::Stdout,
                        format!("active-frame-{index:04}").into_bytes(),
                    ))
                    .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            }
            self.emitted_slots.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
pub struct LogSegmentRaceExecutor {
    first_emitted: AtomicBool,
    second_emitted: AtomicBool,
    emit_second: CancellationToken,
    changed: tokio::sync::Notify,
}

impl LogSegmentRaceExecutor {
    pub fn new() -> Self {
        Self {
            first_emitted: AtomicBool::new(false),
            second_emitted: AtomicBool::new(false),
            emit_second: CancellationToken::new(),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub fn trigger_second_emit(&self) {
        self.emit_second.cancel();
    }

    pub async fn wait_for_first_emit(&self) {
        self.wait_until(&self.first_emitted).await;
    }

    pub async fn wait_for_second_emit(&self) {
        self.wait_until(&self.second_emitted).await;
    }

    pub fn second_emit_finished(&self) -> bool {
        self.second_emitted.load(Ordering::SeqCst)
    }

    async fn wait_until(&self, emitted: &AtomicBool) {
        loop {
            let changed = self.changed.notified();
            if emitted.load(Ordering::SeqCst) {
                return;
            }
            changed.await;
        }
    }
}

impl JobExecutor for LogSegmentRaceExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        _request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            events
                .emit_log(LogEvent::new(LogChannel::Stdout, b"race-frame-0".to_vec()))
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            self.first_emitted.store(true, Ordering::SeqCst);
            self.changed.notify_waiters();

            self.emit_second.cancelled().await;
            events
                .emit_log(LogEvent::new(LogChannel::Stdout, b"race-frame-1".to_vec()))
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            self.second_emitted.store(true, Ordering::SeqCst);
            self.changed.notify_waiters();

            cancellation.token().cancelled().await;
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

impl JobExecutor for BurstLogExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            if self.conclusion != JobConclusion::Skipped {
                events
                    .transition(JobLifecycle::Running)
                    .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                for index in 0..self.data_frames {
                    let payload = format!("frame-{index:04}").into_bytes();
                    events
                        .emit_log(LogEvent::new(LogChannel::Stdout, payload))
                        .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
                }
            }
            Ok(JobResult::new(
                request.lease().attempt_id(),
                self.conclusion,
                JobSecretExposure::Secretless,
                UnixMillis::new(10_001),
            ))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug, Default)]
pub struct LeaseIsolationExecutor {
    survivor_started: AtomicBool,
    expired_reason: Mutex<Option<ExecutionCancellationReason>>,
}

impl LeaseIsolationExecutor {
    pub fn survivor_started(&self) -> bool {
        self.survivor_started.load(Ordering::SeqCst)
    }

    pub fn expired_reason(&self) -> Option<ExecutionCancellationReason> {
        *self
            .expired_reason
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl JobExecutor for LeaseIsolationExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        Ok(ExecutionAdmission::new(sandbox_environment()))
    }

    fn execute(
        &self,
        request: ExecutionRequest,
        events: Arc<dyn ExecutionEvents>,
        cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async move {
            events
                .transition(JobLifecycle::Running)
                .map_err(|_| ExecutorError::new(ExecutorErrorKind::Internal))?;
            if request.slot().get() == 2 {
                self.survivor_started.store(true, Ordering::SeqCst);
            }
            cancellation.token().cancelled().await;
            if request.slot().get() == 1 {
                *self
                    .expired_reason
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = cancellation.reason();
            }
            Err(ExecutorError::new(ExecutorErrorKind::Cancelled))
        })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
pub struct MismatchedEnvironmentExecutor;

impl JobExecutor for MismatchedEnvironmentExecutor {
    fn admit(&self, _job: &JobIrEnvelope) -> Result<ExecutionAdmission, AdmissionRejection> {
        let mismatched = EnvironmentProfile::new(
            EnvironmentProfileId::new("github.com/ubuntu-24.04").expect("profile ID"),
            Sha256Digest::from_bytes([0xb6; 32]),
        );
        Ok(ExecutionAdmission::new(sandbox_environment_for(mismatched)))
    }

    fn execute(
        &self,
        _request: ExecutionRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> ExecutorFuture<'_> {
        Box::pin(async { Err(ExecutorError::new(ExecutorErrorKind::Internal)) })
    }

    fn cleanup(
        &self,
        _request: CleanupRequest,
        _events: Arc<dyn ExecutionEvents>,
        _cancellation: ExecutionCancellation,
    ) -> CleanupFuture<'_> {
        Box::pin(async { Err(ExecutorError::new(ExecutorErrorKind::Internal)) })
    }
}

#[derive(Clone, Debug)]
pub struct ObservedRequest {
    pub operation_id: OperationId,
    pub canonical_bytes: Vec<u8>,
    pub address: usize,
    pub is_hello: bool,
    pub resume: Option<automata_ci_protocol::SessionResume>,
}

#[derive(Debug)]
struct ScriptState {
    handshake_calls: usize,
    poll_calls: usize,
    stale_polls_remaining: usize,
    unavailable_handshakes_remaining: usize,
    observed: Vec<ObservedRequest>,
}

#[derive(Debug)]
pub struct ScriptedControlClient {
    session_id: automata_ci_core::RunnerSessionId,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    state: Mutex<ScriptState>,
}

#[derive(Debug)]
struct RecoveringPollState {
    unavailable_remaining: usize,
    hellos: Vec<ObservedRequest>,
    polls: Vec<ObservedRequest>,
}

#[derive(Debug)]
pub struct RecoveringPollClient {
    session_id: automata_ci_core::RunnerSessionId,
    shutdown_after_recovery: Option<CancellationToken>,
    limits: automata_ci_protocol::ProtocolLimits,
    state: Mutex<RecoveringPollState>,
}

impl RecoveringPollClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        unavailable_attempts: usize,
        shutdown_after_recovery: Option<CancellationToken>,
    ) -> Self {
        Self {
            session_id,
            shutdown_after_recovery,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            state: Mutex::new(RecoveringPollState {
                unavailable_remaining: unavailable_attempts,
                hellos: Vec::new(),
                polls: Vec::new(),
            }),
        }
    }

    pub fn hellos(&self) -> Vec<ObservedRequest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hellos
            .clone()
    }

    pub fn polls(&self) -> Vec<ObservedRequest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .polls
            .clone()
    }
}

impl RunnerRuntimeControlClient for RecoveringPollClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            match request.message() {
                RunnerToServer::Hello(hello) => {
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .hellos
                        .push(observe(request));
                    control_reply(
                        ServerToRunner::Hello(ServerHello::new(
                            OperationId::new(),
                            hello.operation_id(),
                            NegotiatedSession::new(
                                SUPPORTED_PROTOCOL_RANGE.max(),
                                automata_ci_core::JobIrVersion::current(),
                                self.session_id,
                                SessionDisposition::Opened,
                                CommandCursor::initial(),
                            ),
                            ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                        )),
                        &self.limits,
                    )
                }
                RunnerToServer::LeaseRequest(poll) => {
                    let unavailable = {
                        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                        state.polls.push(observe(request));
                        if state.unavailable_remaining == 0 {
                            false
                        } else {
                            state.unavailable_remaining -= 1;
                            true
                        }
                    };
                    if unavailable {
                        return Err(retryable_unavailable());
                    }
                    if let Some(shutdown) = &self.shutdown_after_recovery {
                        shutdown.cancel();
                    }
                    control_reply(
                        ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1)),
                        &self.limits,
                    )
                }
                _ => Err(invalid_control_response()),
            }
        })
    }
}

#[derive(Debug)]
pub struct ResumeFallbackClient {
    stale_session_id: automata_ci_core::RunnerSessionId,
    fresh_session_id: automata_ci_core::RunnerSessionId,
    first_rejection: HandshakeErrorCode,
    fresh_rejection: Option<HandshakeErrorCode>,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    hello_calls: AtomicUsize,
}

impl ResumeFallbackClient {
    pub fn opens_fresh(
        stale_session_id: automata_ci_core::RunnerSessionId,
        fresh_session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
    ) -> Self {
        Self::new(
            stale_session_id,
            fresh_session_id,
            HandshakeErrorCode::SessionNotResumable,
            None,
            shutdown,
        )
    }

    pub fn rejects_fresh(
        stale_session_id: automata_ci_core::RunnerSessionId,
        fresh_session_id: automata_ci_core::RunnerSessionId,
        fresh_rejection: HandshakeErrorCode,
        shutdown: CancellationToken,
    ) -> Self {
        Self::new(
            stale_session_id,
            fresh_session_id,
            HandshakeErrorCode::SessionNotResumable,
            Some(fresh_rejection),
            shutdown,
        )
    }

    pub fn rejects_resume_with(
        stale_session_id: automata_ci_core::RunnerSessionId,
        rejection: HandshakeErrorCode,
        shutdown: CancellationToken,
    ) -> Self {
        Self::new(
            stale_session_id,
            automata_ci_core::RunnerSessionId::new(),
            rejection,
            None,
            shutdown,
        )
    }

    fn new(
        stale_session_id: automata_ci_core::RunnerSessionId,
        fresh_session_id: automata_ci_core::RunnerSessionId,
        first_rejection: HandshakeErrorCode,
        fresh_rejection: Option<HandshakeErrorCode>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            stale_session_id,
            fresh_session_id,
            first_rejection,
            fresh_rejection,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            hello_calls: AtomicUsize::new(0),
        }
    }

    pub fn hello_calls(&self) -> usize {
        self.hello_calls.load(Ordering::SeqCst)
    }

    fn rejection(
        hello: &automata_ci_protocol::RunnerHello,
        code: HandshakeErrorCode,
    ) -> ServerToRunner {
        ServerToRunner::HandshakeRejected(HandshakeRejected::new(
            OperationId::new(),
            hello.operation_id(),
            code,
            SUPPORTED_PROTOCOL_RANGE,
            "scripted handshake rejection",
        ))
    }
}

impl RunnerRuntimeControlClient for ResumeFallbackClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let call = self.hello_calls.fetch_add(1, Ordering::SeqCst);
                    match call {
                        0 => {
                            let resume = hello.resume().expect("first hello resumes");
                            assert_eq!(resume.session_id(), self.stale_session_id);
                            Self::rejection(hello, self.first_rejection)
                        }
                        1 => {
                            assert!(hello.resume().is_none(), "fallback hello must be fresh");
                            if let Some(code) = self.fresh_rejection {
                                Self::rejection(hello, code)
                            } else {
                                ServerToRunner::Hello(ServerHello::new(
                                    OperationId::new(),
                                    hello.operation_id(),
                                    NegotiatedSession::new(
                                        SUPPORTED_PROTOCOL_RANGE.max(),
                                        automata_ci_core::JobIrVersion::current(),
                                        self.fresh_session_id,
                                        SessionDisposition::Opened,
                                        CommandCursor::initial(),
                                    ),
                                    ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                                ))
                            }
                        }
                        _ => panic!("fresh-session fallback must be one-shot"),
                    }
                }
                RunnerToServer::LeaseRequest(poll) => {
                    self.shutdown.cancel();
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug)]
pub struct MaintenanceReapClient {
    stale_session_id: automata_ci_core::RunnerSessionId,
    fresh_session_id: automata_ci_core::RunnerSessionId,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    hello_calls: AtomicUsize,
    poll_calls: AtomicUsize,
}

impl MaintenanceReapClient {
    pub fn new(
        stale_session_id: automata_ci_core::RunnerSessionId,
        fresh_session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            stale_session_id,
            fresh_session_id,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            hello_calls: AtomicUsize::new(0),
            poll_calls: AtomicUsize::new(0),
        }
    }

    pub fn hello_calls(&self) -> usize {
        self.hello_calls.load(Ordering::SeqCst)
    }

    pub fn poll_calls(&self) -> usize {
        self.poll_calls.load(Ordering::SeqCst)
    }

    fn hello(
        hello: &automata_ci_protocol::RunnerHello,
        session_id: automata_ci_core::RunnerSessionId,
    ) -> ServerToRunner {
        ServerToRunner::Hello(ServerHello::new(
            OperationId::new(),
            hello.operation_id(),
            NegotiatedSession::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                automata_ci_core::JobIrVersion::current(),
                session_id,
                SessionDisposition::Opened,
                CommandCursor::initial(),
            ),
            ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
        ))
    }
}

impl RunnerRuntimeControlClient for MaintenanceReapClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let call = self.hello_calls.fetch_add(1, Ordering::SeqCst);
                    match call {
                        0 => {
                            assert!(hello.resume().is_none(), "initial hello must be fresh");
                            Self::hello(hello, self.stale_session_id)
                        }
                        1 => {
                            let resume = hello.resume().expect("reaped session must be resumed");
                            assert_eq!(resume.session_id(), self.stale_session_id);
                            ServerToRunner::HandshakeRejected(HandshakeRejected::new(
                                OperationId::new(),
                                hello.operation_id(),
                                HandshakeErrorCode::SessionNotResumable,
                                SUPPORTED_PROTOCOL_RANGE,
                                "scripted maintenance reap",
                            ))
                        }
                        2 => {
                            assert!(
                                hello.resume().is_none(),
                                "non-resumable empty session must fall back to one fresh hello"
                            );
                            Self::hello(hello, self.fresh_session_id)
                        }
                        _ => panic!("maintenance recovery must open exactly one fresh session"),
                    }
                }
                RunnerToServer::LeaseRequest(poll) => {
                    let call = self.poll_calls.fetch_add(1, Ordering::SeqCst);
                    match call {
                        0 => {
                            assert_eq!(poll.header().session_id(), self.stale_session_id);
                            ServerToRunner::Error(ErrorMessage::new(
                                reply_header(poll.header()),
                                RemoteErrorCode::StaleSession,
                                "scripted maintenance reap",
                                false,
                            ))
                        }
                        1 => {
                            assert_eq!(poll.header().session_id(), self.fresh_session_id);
                            self.shutdown.cancel();
                            ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                        }
                        _ => panic!("fresh session must stop after its first successful poll"),
                    }
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug)]
pub struct CrossSlotReplayClient {
    session_id: automata_ci_core::RunnerSessionId,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    offer: LeaseOffer,
    delivery_barrier: tokio::sync::Barrier,
    acknowledgement_calls: AtomicUsize,
}

impl CrossSlotReplayClient {
    pub fn new(
        runner_id: RunnerId,
        session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
    ) -> Self {
        Self::with_target_slot(runner_id, session_id, shutdown, 1)
    }

    pub fn with_out_of_range_target(
        runner_id: RunnerId,
        session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
    ) -> Self {
        Self::with_target_slot(runner_id, session_id, shutdown, 3)
    }

    fn with_target_slot(
        runner_id: RunnerId,
        session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
        target_slot: u16,
    ) -> Self {
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(7).expect("fencing token"),
            UnixMillis::new(9_000),
            UnixMillis::new(40_000),
        )
        .expect("lease");
        let job = minimal_job();
        let authorities = test_runtime_authorities(&job, &lease);
        let offer = LeaseOffer::new(
            ServerCommandHeader::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                session_id,
                OperationId::new(),
                CommandSequence::new(1).expect("first command"),
            ),
            RunnerSlotOrdinal::new(target_slot).expect("target slot"),
            lease,
            job,
            authorities,
        );
        Self {
            session_id,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            offer,
            delivery_barrier: tokio::sync::Barrier::new(2),
            acknowledgement_calls: AtomicUsize::new(0),
        }
    }

    pub fn acknowledgement_calls(&self) -> usize {
        self.acknowledgement_calls.load(Ordering::SeqCst)
    }
}

impl RunnerRuntimeControlClient for CrossSlotReplayClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            match request.message() {
                RunnerToServer::Hello(hello) => control_reply(
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Opened,
                            CommandCursor::initial(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    )),
                    &self.limits,
                ),
                RunnerToServer::LeaseRequest(poll) => {
                    assert!(poll.slot().get() <= 2, "only two slots are configured");
                    tokio::select! {
                        _ = self.delivery_barrier.wait() => {}
                        () = cancellation.cancelled() => {
                            return Err(RuntimeControlError::new(
                                RuntimeControlErrorKind::Cancelled,
                                RuntimeControlRetry::Never,
                            ));
                        }
                    }
                    control_reply(
                        ServerToRunner::LeaseOffer(Box::new(self.offer.clone())),
                        &self.limits,
                    )
                }
                RunnerToServer::CommandAck(ack) => {
                    assert_eq!(
                        ack.command_cursor(),
                        CommandCursor::through(CommandSequence::new(1).expect("first command"))
                    );
                    let call = self.acknowledgement_calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(call, 0, "a piggyback response commits the cumulative ACK");
                    // The handler commits the ACK before selecting an
                    // unacknowledged command for its correlated response.
                    tokio::task::yield_now().await;
                    self.shutdown.cancel();
                    control_reply(
                        ServerToRunner::LeaseOffer(Box::new(self.offer.clone())),
                        &self.limits,
                    )
                }
                _ => Err(invalid_control_response()),
            }
        })
    }
}

#[derive(Debug, Default)]
struct CommandDuringAckState {
    acknowledgements: Vec<(u64, ObservedRequest)>,
    running_heartbeats: Vec<AttemptId>,
}

#[derive(Debug)]
pub struct CommandDuringAckClient {
    session_id: automata_ci_core::RunnerSessionId,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    offers: [LeaseOffer; 2],
    delivery_barrier: tokio::sync::Barrier,
    second_ack_calls: AtomicUsize,
    state: Mutex<CommandDuringAckState>,
}

impl CommandDuringAckClient {
    pub fn new(
        runner_id: RunnerId,
        session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            session_id,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            offers: [
                Self::offer(runner_id, session_id, 1, 1, 7),
                Self::offer(runner_id, session_id, 2, 2, 8),
            ],
            delivery_barrier: tokio::sync::Barrier::new(2),
            second_ack_calls: AtomicUsize::new(0),
            state: Mutex::new(CommandDuringAckState::default()),
        }
    }

    fn offer(
        runner_id: RunnerId,
        session_id: automata_ci_core::RunnerSessionId,
        sequence: u64,
        slot: u16,
        fencing_token: u64,
    ) -> LeaseOffer {
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(fencing_token).expect("fencing token"),
            UnixMillis::new(9_000),
            UnixMillis::new(40_000),
        )
        .expect("lease");
        let job = minimal_job();
        let authorities = test_runtime_authorities(&job, &lease);
        LeaseOffer::new(
            ServerCommandHeader::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                session_id,
                OperationId::new(),
                CommandSequence::new(sequence).expect("command sequence"),
            ),
            RunnerSlotOrdinal::new(slot).expect("runner slot"),
            lease,
            job,
            authorities,
        )
    }

    pub fn acknowledgement_cursors(&self) -> Vec<u64> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .acknowledgements
            .iter()
            .map(|(cursor, _)| *cursor)
            .collect()
    }

    pub fn acknowledgement_requests(&self, cursor: u64) -> Vec<ObservedRequest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .acknowledgements
            .iter()
            .filter(|(observed, _)| *observed == cursor)
            .map(|(_, request)| request.clone())
            .collect()
    }

    pub fn expected_attempts(&self) -> Vec<AttemptId> {
        self.offers
            .iter()
            .map(|offer| offer.lease().attempt_id())
            .collect()
    }

    pub fn running_heartbeats(&self) -> Vec<AttemptId> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .running_heartbeats
            .clone()
    }
}

impl RunnerRuntimeControlClient for CommandDuringAckClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => ServerToRunner::Hello(ServerHello::new(
                    OperationId::new(),
                    hello.operation_id(),
                    NegotiatedSession::new(
                        SUPPORTED_PROTOCOL_RANGE.max(),
                        automata_ci_core::JobIrVersion::current(),
                        self.session_id,
                        SessionDisposition::Opened,
                        CommandCursor::initial(),
                    ),
                    ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                )),
                RunnerToServer::LeaseRequest(poll) => {
                    assert!(poll.slot().get() <= 2, "only two slots are configured");
                    tokio::select! {
                        _ = self.delivery_barrier.wait() => {}
                        () = cancellation.cancelled() => {
                            return Err(RuntimeControlError::new(
                                RuntimeControlErrorKind::Cancelled,
                                RuntimeControlRetry::Never,
                            ));
                        }
                    }
                    ServerToRunner::LeaseOffer(Box::new(self.offers[0].clone()))
                }
                RunnerToServer::CommandAck(ack) => {
                    let cursor = ack
                        .command_cursor()
                        .acknowledged_through()
                        .expect("non-empty command ACK")
                        .get();
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .acknowledgements
                        .push((cursor, observe(request)));
                    match cursor {
                        1 => ServerToRunner::LeaseOffer(Box::new(self.offers[1].clone())),
                        2 => {
                            let call = self.second_ack_calls.fetch_add(1, Ordering::SeqCst);
                            if call == 0 {
                                return Err(retryable_unavailable());
                            }
                            assert_eq!(call, 1, "the rebuilt ACK retries exactly once");
                            ServerToRunner::OperationAck(OperationAck::new(reply_header(
                                ack.header(),
                            )))
                        }
                        _ => panic!("unexpected command cursor {cursor}"),
                    }
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    tokio::task::yield_now().await;
                    if heartbeat.lifecycle() == JobLifecycle::Running {
                        let complete = {
                            let mut state =
                                self.state.lock().unwrap_or_else(PoisonError::into_inner);
                            if !state.running_heartbeats.contains(&heartbeat.attempt_id()) {
                                state.running_heartbeats.push(heartbeat.attempt_id());
                            }
                            self.offers.iter().all(|offer| {
                                state
                                    .running_heartbeats
                                    .contains(&offer.lease().attempt_id())
                            })
                        };
                        if complete {
                            self.shutdown.cancel();
                        }
                    }
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        heartbeat.attempt_id(),
                        heartbeat.guard(),
                        UnixMillis::new(50_000),
                    ))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug)]
pub struct DelayedPredecessorClient {
    session_id: automata_ci_core::RunnerSessionId,
    shutdown: CancellationToken,
    sleeper: Arc<CommandGapSleeper>,
    limits: automata_ci_protocol::ProtocolLimits,
    offers: [LeaseOffer; 2],
    slot_one_polls: AtomicUsize,
    slot_two_polls: AtomicUsize,
    acknowledgement_cursors: Mutex<Vec<u64>>,
}

impl DelayedPredecessorClient {
    pub fn new(
        runner_id: RunnerId,
        session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
        sleeper: Arc<CommandGapSleeper>,
    ) -> Self {
        Self {
            session_id,
            shutdown,
            sleeper,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            offers: [
                CommandDuringAckClient::offer(runner_id, session_id, 1, 1, 7),
                CommandDuringAckClient::offer(runner_id, session_id, 2, 2, 8),
            ],
            slot_one_polls: AtomicUsize::new(0),
            slot_two_polls: AtomicUsize::new(0),
            acknowledgement_cursors: Mutex::new(Vec::new()),
        }
    }

    pub fn acknowledgement_cursors(&self) -> Vec<u64> {
        self.acknowledgement_cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RunnerRuntimeControlClient for DelayedPredecessorClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => ServerToRunner::Hello(ServerHello::new(
                    OperationId::new(),
                    hello.operation_id(),
                    NegotiatedSession::new(
                        SUPPORTED_PROTOCOL_RANGE.max(),
                        automata_ci_core::JobIrVersion::current(),
                        self.session_id,
                        SessionDisposition::Opened,
                        CommandCursor::initial(),
                    ),
                    ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                )),
                RunnerToServer::LeaseRequest(poll) => {
                    let (calls, offer) = if poll.slot().get() == 1 {
                        (&self.slot_one_polls, &self.offers[0])
                    } else {
                        assert_eq!(poll.slot().get(), 2, "only two slots are configured");
                        (&self.slot_two_polls, &self.offers[1])
                    };
                    if calls.fetch_add(1, Ordering::SeqCst) > 0 {
                        cancellation.cancelled().await;
                        return Err(RuntimeControlError::new(
                            RuntimeControlErrorKind::Cancelled,
                            RuntimeControlRetry::Never,
                        ));
                    }
                    if poll.slot().get() == 1
                        && !self.sleeper.wait_for_calls(5, &cancellation).await
                    {
                        return Err(RuntimeControlError::new(
                            RuntimeControlErrorKind::Cancelled,
                            RuntimeControlRetry::Never,
                        ));
                    }
                    ServerToRunner::LeaseOffer(Box::new(offer.clone()))
                }
                RunnerToServer::CommandAck(ack) => {
                    let cursor = ack
                        .command_cursor()
                        .acknowledged_through()
                        .expect("non-empty command ACK")
                        .get();
                    self.acknowledgement_cursors
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(cursor);
                    if cursor == 2 {
                        self.shutdown.cancel();
                    }
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(ack.header())))
                }
                RunnerToServer::LeaseResponse(response) => {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug)]
pub struct IgnoredOfferReplayClient {
    session_id: automata_ci_core::RunnerSessionId,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    offers: [LeaseOffer; 2],
    poll_calls: AtomicUsize,
    replay_seen: AtomicBool,
    acknowledgement_cursors: Mutex<Vec<u64>>,
}

impl IgnoredOfferReplayClient {
    pub fn new(
        runner_id: RunnerId,
        session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            session_id,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            offers: [
                CommandDuringAckClient::offer(runner_id, session_id, 1, 1, 7),
                CommandDuringAckClient::offer(runner_id, session_id, 2, 1, 8),
            ],
            poll_calls: AtomicUsize::new(0),
            replay_seen: AtomicBool::new(false),
            acknowledgement_cursors: Mutex::new(Vec::new()),
        }
    }

    pub fn replay_seen(&self) -> bool {
        self.replay_seen.load(Ordering::SeqCst)
    }

    pub fn acknowledgement_cursors(&self) -> Vec<u64> {
        self.acknowledgement_cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RunnerRuntimeControlClient for IgnoredOfferReplayClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => ServerToRunner::Hello(ServerHello::new(
                    OperationId::new(),
                    hello.operation_id(),
                    NegotiatedSession::new(
                        SUPPORTED_PROTOCOL_RANGE.max(),
                        automata_ci_core::JobIrVersion::current(),
                        self.session_id,
                        SessionDisposition::Opened,
                        CommandCursor::initial(),
                    ),
                    ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                )),
                RunnerToServer::LeaseRequest(poll) => {
                    match self.poll_calls.fetch_add(1, Ordering::SeqCst) {
                        0 => ServerToRunner::LeaseOffer(Box::new(self.offers[0].clone())),
                        1 => {
                            self.replay_seen.store(true, Ordering::SeqCst);
                            ServerToRunner::LeaseOffer(Box::new(self.offers[1].clone()))
                        }
                        _ => {
                            self.shutdown.cancel();
                            ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                        }
                    }
                }
                RunnerToServer::CommandAck(ack) => {
                    let cursor = ack
                        .command_cursor()
                        .acknowledged_through()
                        .expect("non-empty command ACK")
                        .get();
                    self.acknowledgement_cursors
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(cursor);
                    if cursor == 1 {
                        ServerToRunner::LeaseOffer(Box::new(self.offers[1].clone()))
                    } else {
                        assert_eq!(cursor, 2, "only two commands are scripted");
                        ServerToRunner::OperationAck(OperationAck::new(reply_header(ack.header())))
                    }
                }
                RunnerToServer::LeaseResponse(response) => {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

impl ScriptedControlClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        shutdown: CancellationToken,
        unavailable_handshakes: usize,
        stale_polls: usize,
    ) -> Self {
        Self {
            session_id,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            state: Mutex::new(ScriptState {
                handshake_calls: 0,
                poll_calls: 0,
                stale_polls_remaining: stale_polls,
                unavailable_handshakes_remaining: unavailable_handshakes,
                observed: Vec::new(),
            }),
        }
    }

    pub fn observed(&self) -> Vec<ObservedRequest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observed
            .clone()
    }
}

impl RunnerRuntimeControlClient for ScriptedControlClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let (is_hello, resume) = match request.message() {
                RunnerToServer::Hello(hello) => (true, hello.resume()),
                _ => (false, None),
            };
            state.observed.push(ObservedRequest {
                operation_id: request.operation_id(),
                canonical_bytes: request.canonical_bytes().to_vec(),
                address: std::ptr::from_ref(request) as usize,
                is_hello,
                resume,
            });
            match request.message() {
                RunnerToServer::Hello(hello) => {
                    state.handshake_calls += 1;
                    if state.unavailable_handshakes_remaining > 0 {
                        state.unavailable_handshakes_remaining -= 1;
                        return Err(RuntimeControlError::new(
                            RuntimeControlErrorKind::Unavailable,
                            RuntimeControlRetry::SamePreparedRequest,
                        ));
                    }
                    let (disposition, cursor) = hello.resume().map_or(
                        (SessionDisposition::Opened, CommandCursor::initial()),
                        |resume| {
                            assert_eq!(resume.session_id(), self.session_id);
                            (SessionDisposition::Resumed, resume.command_cursor())
                        },
                    );
                    RuntimeControlReply::from_message(
                        ServerToRunner::Hello(ServerHello::new(
                            OperationId::new(),
                            hello.operation_id(),
                            NegotiatedSession::new(
                                SUPPORTED_PROTOCOL_RANGE.max(),
                                automata_ci_core::JobIrVersion::current(),
                                self.session_id,
                                disposition,
                                cursor,
                            ),
                            ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                        )),
                        &self.limits,
                    )
                    .map_err(|_| {
                        RuntimeControlError::new(
                            RuntimeControlErrorKind::InvalidResponse,
                            RuntimeControlRetry::Never,
                        )
                    })
                }
                RunnerToServer::LeaseRequest(poll) => {
                    state.poll_calls += 1;
                    if state.stale_polls_remaining > 0 {
                        state.stale_polls_remaining -= 1;
                        return RuntimeControlReply::from_message(
                            ServerToRunner::Error(ErrorMessage::new(
                                reply_header(poll.header()),
                                RemoteErrorCode::StaleSession,
                                "stale",
                                false,
                            )),
                            &self.limits,
                        )
                        .map_err(|_| {
                            RuntimeControlError::new(
                                RuntimeControlErrorKind::InvalidResponse,
                                RuntimeControlRetry::Never,
                            )
                        });
                    }
                    self.shutdown.cancel();
                    RuntimeControlReply::from_message(
                        ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1)),
                        &self.limits,
                    )
                    .map_err(|_| {
                        RuntimeControlError::new(
                            RuntimeControlErrorKind::InvalidResponse,
                            RuntimeControlRetry::Never,
                        )
                    })
                }
                _ => Err(RuntimeControlError::new(
                    RuntimeControlErrorKind::InvalidResponse,
                    RuntimeControlRetry::Never,
                )),
            }
        })
    }
}

#[derive(Debug)]
pub struct AcceptanceClient {
    session_id: automata_ci_core::RunnerSessionId,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    acceptances: Mutex<Vec<ObservedRequest>>,
}

impl AcceptanceClient {
    pub fn new(session_id: automata_ci_core::RunnerSessionId, shutdown: CancellationToken) -> Self {
        Self {
            session_id,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            acceptances: Mutex::new(Vec::new()),
        }
    }

    pub fn acceptance(&self) -> ObservedRequest {
        self.acceptances
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .first()
            .cloned()
            .expect("acceptance request")
    }
}

impl RunnerRuntimeControlClient for AcceptanceClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    assert_eq!(resume.session_id(), self.session_id);
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    self.acceptances
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(ObservedRequest {
                            operation_id: request.operation_id(),
                            canonical_bytes: request.canonical_bytes().to_vec(),
                            address: std::ptr::from_ref(request) as usize,
                            is_hello: false,
                            resume: None,
                        });
                    self.shutdown.cancel();
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                _ => {
                    return Err(RuntimeControlError::new(
                        RuntimeControlErrorKind::InvalidResponse,
                        RuntimeControlRetry::Never,
                    ));
                }
            };
            RuntimeControlReply::from_message(response, &self.limits).map_err(|_| {
                RuntimeControlError::new(
                    RuntimeControlErrorKind::InvalidResponse,
                    RuntimeControlRetry::Never,
                )
            })
        })
    }
}

#[derive(Debug)]
pub struct RejectionClient {
    session_id: automata_ci_core::RunnerSessionId,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    rejection: Mutex<Option<automata_ci_protocol::LeaseRejectionReason>>,
}

impl RejectionClient {
    pub fn new(session_id: automata_ci_core::RunnerSessionId, shutdown: CancellationToken) -> Self {
        Self {
            session_id,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            rejection: Mutex::new(None),
        }
    }

    pub fn rejection(&self) -> Option<automata_ci_protocol::LeaseRejectionReason> {
        self.rejection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RunnerRuntimeControlClient for RejectionClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => ServerToRunner::Hello(ServerHello::new(
                    OperationId::new(),
                    hello.operation_id(),
                    NegotiatedSession::new(
                        SUPPORTED_PROTOCOL_RANGE.max(),
                        automata_ci_core::JobIrVersion::current(),
                        self.session_id,
                        SessionDisposition::Resumed,
                        hello.resume().expect("recovery hello").command_cursor(),
                    ),
                    ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                )),
                RunnerToServer::LeaseResponse(response) => {
                    let automata_ci_protocol::LeaseDisposition::Rejected(reason) =
                        response.disposition()
                    else {
                        return Err(invalid_control_response());
                    };
                    *self
                        .rejection
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = Some(reason.clone());
                    self.shutdown.cancel();
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug, Default)]
struct CancellationFlowState {
    cancel_sent: bool,
    cancel_replayed_after_release: bool,
    log_requests: Vec<ObservedRequest>,
    result_requests: Vec<ObservedRequest>,
}

#[derive(Debug)]
pub struct CancellationFlowClient {
    session_id: automata_ci_core::RunnerSessionId,
    lease: Lease,
    running: Arc<AtomicBool>,
    shutdown: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    cancellation: CancelJob,
    state: Mutex<CancellationFlowState>,
}

impl CancellationFlowClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        lease: Lease,
        running: Arc<AtomicBool>,
        shutdown: CancellationToken,
    ) -> Self {
        let cancellation = CancelJob::new(
            ServerCommandHeader::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                session_id,
                OperationId::new(),
                CommandSequence::new(2).expect("second command"),
            ),
            lease.attempt_id(),
            lease.guard(),
            "test cancellation",
            UnixMillis::new(10_001),
        );
        Self {
            session_id,
            lease,
            running,
            shutdown,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            cancellation,
            state: Mutex::new(CancellationFlowState::default()),
        }
    }

    pub fn log_requests(&self) -> Vec<ObservedRequest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .log_requests
            .clone()
    }

    pub fn result_requests(&self) -> Vec<ObservedRequest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .result_requests
            .clone()
    }

    pub fn cancel_replayed_after_release(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cancel_replayed_after_release
    }
}

impl RunnerRuntimeControlClient for CancellationFlowClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    if self.running.load(Ordering::SeqCst) && !state.cancel_sent {
                        state.cancel_sent = true;
                        ServerToRunner::CancelJob(self.cancellation.clone())
                    } else {
                        ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                            reply_header(heartbeat.header()),
                            self.lease.attempt_id(),
                            self.lease.guard(),
                            UnixMillis::new(50_000),
                        ))
                    }
                }
                RunnerToServer::CommandAck(ack) => {
                    assert_eq!(
                        ack.command_cursor(),
                        CommandCursor::through(CommandSequence::new(2).expect("second command"))
                    );
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(ack.header())))
                }
                RunnerToServer::LogBatch(batch) => {
                    let frame = batch.frames().first().expect("one log frame");
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    state.log_requests.push(observe(request));
                    if state.log_requests.len() == 1 {
                        return Err(retryable_unavailable());
                    }
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        LogAck::new(frame.stream_id(), Some(frame.sequence())),
                    ))
                }
                RunnerToServer::JobResult(result) => {
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    state.result_requests.push(observe(request));
                    if state.result_requests.len() == 1 {
                        return Err(retryable_unavailable());
                    }
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(result.header())))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    if state.cancel_replayed_after_release {
                        self.shutdown.cancel();
                        ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                    } else {
                        state.cancel_replayed_after_release = true;
                        ServerToRunner::CancelJob(self.cancellation.clone())
                    }
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug, Default)]
struct CancellationContentRaceState {
    cancel_sent: bool,
    released_slot_polled: bool,
    terminal_results: Vec<(AttemptId, JobConclusion)>,
}

#[derive(Debug)]
pub struct CancellationContentRaceClient {
    session_id: automata_ci_core::RunnerSessionId,
    executor: Arc<CancellationContentRaceExecutor>,
    probe: ContentRaceProbe,
    cancellation: CancelJob,
    limits: automata_ci_protocol::ProtocolLimits,
    changed: tokio::sync::Notify,
    state: Mutex<CancellationContentRaceState>,
}

impl CancellationContentRaceClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        cancelled_lease: &Lease,
        executor: Arc<CancellationContentRaceExecutor>,
        probe: ContentRaceProbe,
    ) -> Self {
        let cancellation = CancelJob::new(
            ServerCommandHeader::new(
                SUPPORTED_PROTOCOL_RANGE.max(),
                session_id,
                OperationId::new(),
                CommandSequence::new(3).expect("third command"),
            ),
            cancelled_lease.attempt_id(),
            cancelled_lease.guard(),
            "publication reconciliation race",
            UnixMillis::new(10_001),
        );
        Self {
            session_id,
            executor,
            probe,
            cancellation,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            changed: tokio::sync::Notify::new(),
            state: Mutex::new(CancellationContentRaceState::default()),
        }
    }

    pub async fn wait_for_cancel(&self) {
        self.wait_until(|state| state.cancel_sent).await;
    }

    pub async fn wait_for_released_slot_poll(&self) {
        self.wait_until(|state| state.released_slot_polled).await;
    }

    pub fn terminal_results(&self) -> Vec<(AttemptId, JobConclusion)> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .terminal_results
            .clone()
    }

    async fn wait_until(&self, predicate: impl Fn(&CancellationContentRaceState) -> bool) {
        loop {
            let changed = self.changed.notified();
            if predicate(&self.state.lock().unwrap_or_else(PoisonError::into_inner)) {
                return;
            }
            changed.await;
        }
    }
}

impl RunnerRuntimeControlClient for CancellationContentRaceClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    let send_cancel = {
                        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                        let send = !state.cancel_sent
                            && self.executor.cancellation_ready()
                            && self.probe.cancellation_may_be_sent();
                        if send {
                            state.cancel_sent = true;
                            self.changed.notify_waiters();
                        }
                        send
                    };
                    if send_cancel {
                        ServerToRunner::CancelJob(self.cancellation.clone())
                    } else {
                        ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                            reply_header(heartbeat.header()),
                            heartbeat.attempt_id(),
                            heartbeat.guard(),
                            UnixMillis::new(50_000),
                        ))
                    }
                }
                RunnerToServer::CommandAck(ack) => {
                    assert_eq!(
                        ack.command_cursor(),
                        CommandCursor::through(CommandSequence::new(3).expect("third command"))
                    );
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(ack.header())))
                }
                RunnerToServer::LogBatch(batch) => {
                    let last = batch.frames().last().expect("nonempty log batch");
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        LogAck::new(last.stream_id(), Some(last.sequence())),
                    ))
                }
                RunnerToServer::JobResult(result) => {
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .terminal_results
                        .push((result.result().attempt_id(), result.result().conclusion()));
                    self.changed.notify_waiters();
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(result.header())))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    if poll.slot().get() == 1 {
                        self.state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .released_slot_polled = true;
                        self.changed.notify_waiters();
                    }
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug)]
pub struct DisconnectedHeartbeatClient {
    session_id: automata_ci_core::RunnerSessionId,
    clock: Arc<ManualClock>,
    limits: automata_ci_protocol::ProtocolLimits,
    heartbeat_requests: Mutex<Vec<ObservedRequest>>,
}

#[derive(Debug)]
struct RecoveringHeartbeatState {
    unavailable_remaining: usize,
    recovered: bool,
    outage_requests: Vec<ObservedRequest>,
}

#[derive(Debug)]
pub struct RecoveringHeartbeatClient {
    session_id: automata_ci_core::RunnerSessionId,
    lease: Lease,
    limits: automata_ci_protocol::ProtocolLimits,
    recovered: tokio::sync::Notify,
    state: Mutex<RecoveringHeartbeatState>,
}

impl RecoveringHeartbeatClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        lease: Lease,
        unavailable_attempts: usize,
    ) -> Self {
        Self {
            session_id,
            lease,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            recovered: tokio::sync::Notify::new(),
            state: Mutex::new(RecoveringHeartbeatState {
                unavailable_remaining: unavailable_attempts,
                recovered: false,
                outage_requests: Vec::new(),
            }),
        }
    }

    pub async fn wait_until_recovered(&self) {
        self.recovered.notified().await;
    }

    pub fn outage_requests(&self) -> Vec<ObservedRequest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .outage_requests
            .clone()
    }
}

impl RunnerRuntimeControlClient for RecoveringHeartbeatClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    let unavailable = {
                        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                        if state.recovered {
                            false
                        } else {
                            state.outage_requests.push(observe(request));
                            if state.unavailable_remaining == 0 {
                                state.recovered = true;
                                self.recovered.notify_one();
                                false
                            } else {
                                state.unavailable_remaining -= 1;
                                true
                            }
                        }
                    };
                    if unavailable {
                        return Err(retryable_unavailable());
                    }
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        self.lease.attempt_id(),
                        self.lease.guard(),
                        UnixMillis::new(50_000),
                    ))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug, Default)]
struct FailureIsolationState {
    terminal_results: Vec<(AttemptId, JobConclusion)>,
    terminal_secret_exposures: Vec<JobSecretExposure>,
    log_frames: Vec<LogFrame>,
    log_receipts: BTreeMap<OperationId, Vec<u8>>,
    terminal_results_after_eos: Vec<bool>,
    heartbeat_lifecycles: Vec<JobLifecycle>,
}

#[derive(Debug)]
pub struct FailureIsolationClient {
    session_id: automata_ci_core::RunnerSessionId,
    limits: automata_ci_protocol::ProtocolLimits,
    terminal_result: tokio::sync::Notify,
    released_slot_poll: tokio::sync::Notify,
    state: Mutex<FailureIsolationState>,
}

impl FailureIsolationClient {
    pub fn new(session_id: automata_ci_core::RunnerSessionId) -> Self {
        Self {
            session_id,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            terminal_result: tokio::sync::Notify::new(),
            released_slot_poll: tokio::sync::Notify::new(),
            state: Mutex::new(FailureIsolationState::default()),
        }
    }

    pub async fn wait_for_terminal_result(&self) {
        self.terminal_result.notified().await;
    }

    pub async fn wait_for_released_slot_poll(&self) {
        self.released_slot_poll.notified().await;
    }

    pub fn terminal_results(&self) -> Vec<(AttemptId, JobConclusion)> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .terminal_results
            .clone()
    }

    pub fn terminal_secret_exposures(&self) -> Vec<JobSecretExposure> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .terminal_secret_exposures
            .clone()
    }

    pub fn log_frames(&self) -> Vec<LogFrame> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .log_frames
            .clone()
    }

    pub fn terminal_results_after_eos(&self) -> Vec<bool> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .terminal_results_after_eos
            .clone()
    }

    pub fn heartbeat_lifecycles(&self) -> Vec<JobLifecycle> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .heartbeat_lifecycles
            .clone()
    }
}

impl RunnerRuntimeControlClient for FailureIsolationClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .heartbeat_lifecycles
                        .push(heartbeat.lifecycle());
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        heartbeat.attempt_id(),
                        heartbeat.guard(),
                        UnixMillis::new(50_000),
                    ))
                }
                RunnerToServer::LogBatch(batch) => {
                    let last = batch.frames().last().expect("nonempty log batch");
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Some(canonical) = state.log_receipts.get(&batch.header().operation_id())
                    {
                        // A lost acknowledgement may replay the stable operation, just as the
                        // real control handler replays its durable receipt without appending.
                        assert_eq!(
                            canonical.as_slice(),
                            request.canonical_bytes().as_ref(),
                            "a log receipt only replays for the exact canonical request"
                        );
                    } else {
                        state.log_frames.extend(batch.frames().iter().cloned());
                        state.log_receipts.insert(
                            batch.header().operation_id(),
                            request.canonical_bytes().to_vec(),
                        );
                    }
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        LogAck::new(last.stream_id(), Some(last.sequence())),
                    ))
                }
                RunnerToServer::JobResult(result) => {
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    let after_eos = state
                        .log_frames
                        .last()
                        .is_some_and(LogFrame::is_end_of_stream);
                    state.terminal_results_after_eos.push(after_eos);
                    state
                        .terminal_results
                        .push((result.result().attempt_id(), result.result().conclusion()));
                    state
                        .terminal_secret_exposures
                        .push(result.result().secret_exposure());
                    self.terminal_result.notify_one();
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(result.header())))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    if poll.slot().get() == 1 {
                        self.released_slot_poll.notify_one();
                    }
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug)]
pub struct CleanupIsolationClient {
    session_id: automata_ci_core::RunnerSessionId,
    failed_attempt: AttemptId,
    survivor_attempt: AttemptId,
    limits: automata_ci_protocol::ProtocolLimits,
    finalizing_heartbeats: AtomicUsize,
    survivor_heartbeats: AtomicUsize,
    survivor_logs: AtomicUsize,
    terminal_results: Mutex<Vec<(AttemptId, JobConclusion)>>,
    released_slot_poll: tokio::sync::Notify,
    order_probe: Option<Arc<TerminalCleanupOrderProbe>>,
}

impl CleanupIsolationClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        failed_attempt: AttemptId,
        survivor_attempt: AttemptId,
    ) -> Self {
        Self {
            session_id,
            failed_attempt,
            survivor_attempt,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            finalizing_heartbeats: AtomicUsize::new(0),
            survivor_heartbeats: AtomicUsize::new(0),
            survivor_logs: AtomicUsize::new(0),
            terminal_results: Mutex::new(Vec::new()),
            released_slot_poll: tokio::sync::Notify::new(),
            order_probe: None,
        }
    }

    pub fn with_order_probe(mut self, order_probe: Arc<TerminalCleanupOrderProbe>) -> Self {
        self.order_probe = Some(order_probe);
        self
    }

    pub fn finalizing_heartbeats(&self) -> usize {
        self.finalizing_heartbeats.load(Ordering::SeqCst)
    }

    pub fn survivor_heartbeats(&self) -> usize {
        self.survivor_heartbeats.load(Ordering::SeqCst)
    }

    pub fn survivor_logs(&self) -> usize {
        self.survivor_logs.load(Ordering::SeqCst)
    }

    pub fn terminal_results(&self) -> Vec<(AttemptId, JobConclusion)> {
        self.terminal_results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub async fn wait_for_released_slot_poll(&self) {
        self.released_slot_poll.notified().await;
    }
}

impl RunnerRuntimeControlClient for CleanupIsolationClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    if heartbeat.attempt_id() == self.failed_attempt
                        && heartbeat.lifecycle() == JobLifecycle::Finalizing
                    {
                        self.finalizing_heartbeats.fetch_add(1, Ordering::SeqCst);
                    }
                    if heartbeat.attempt_id() == self.survivor_attempt
                        && heartbeat.lifecycle() == JobLifecycle::Running
                    {
                        self.survivor_heartbeats.fetch_add(1, Ordering::SeqCst);
                    }
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        heartbeat.attempt_id(),
                        heartbeat.guard(),
                        UnixMillis::new(50_000),
                    ))
                }
                RunnerToServer::LogBatch(batch) => {
                    let last = batch.frames().last().expect("nonempty log batch");
                    if last.attempt_id() == self.survivor_attempt {
                        self.survivor_logs.fetch_add(1, Ordering::SeqCst);
                    }
                    if last.attempt_id() == self.failed_attempt
                        && let Some(probe) = &self.order_probe
                    {
                        probe.record(if last.is_end_of_stream() {
                            TerminalCleanupStage::EosAcknowledged
                        } else {
                            TerminalCleanupStage::PayloadAcknowledged
                        });
                    }
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        automata_ci_core::LogAck::new(last.stream_id(), Some(last.sequence())),
                    ))
                }
                RunnerToServer::JobResult(result) => {
                    if result.result().attempt_id() == self.failed_attempt
                        && let Some(probe) = &self.order_probe
                    {
                        probe.record(TerminalCleanupStage::TerminalResultDelivered);
                    }
                    self.terminal_results
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((result.result().attempt_id(), result.result().conclusion()));
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(result.header())))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    if poll.slot().get() == 1 {
                        if let Some(probe) = &self.order_probe {
                            probe.record(TerminalCleanupStage::ReleasedSlotPolled);
                        }
                        self.released_slot_poll.notify_one();
                    }
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

impl DisconnectedHeartbeatClient {
    pub fn new(session_id: automata_ci_core::RunnerSessionId, clock: Arc<ManualClock>) -> Self {
        Self {
            session_id,
            clock,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            heartbeat_requests: Mutex::new(Vec::new()),
        }
    }

    pub fn heartbeat_requests(&self) -> Vec<ObservedRequest> {
        self.heartbeat_requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RunnerRuntimeControlClient for DisconnectedHeartbeatClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            match request.message() {
                RunnerToServer::Hello(hello) => control_reply(
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            hello.resume().expect("recovery hello").command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    )),
                    &self.limits,
                ),
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    control_reply(
                        ServerToRunner::OperationAck(OperationAck::new(reply_header(
                            response.header(),
                        ))),
                        &self.limits,
                    )
                }
                RunnerToServer::Heartbeat(_) => {
                    self.heartbeat_requests
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(observe(request));
                    self.clock.set_monotonic(50_000);
                    Err(retryable_unavailable())
                }
                _ => Err(invalid_control_response()),
            }
        })
    }
}

#[derive(Debug)]
pub struct LeaseIsolationClient {
    session_id: automata_ci_core::RunnerSessionId,
    expiring_lease: Lease,
    surviving_lease: Lease,
    clock: Arc<ManualClock>,
    limits: automata_ci_protocol::ProtocolLimits,
    expiring_requests: Mutex<Vec<ObservedRequest>>,
    surviving_heartbeats: AtomicUsize,
}

impl LeaseIsolationClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        expiring_lease: Lease,
        surviving_lease: Lease,
        clock: Arc<ManualClock>,
    ) -> Self {
        Self {
            session_id,
            expiring_lease,
            surviving_lease,
            clock,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            expiring_requests: Mutex::new(Vec::new()),
            surviving_heartbeats: AtomicUsize::new(0),
        }
    }

    pub fn expiring_requests(&self) -> Vec<ObservedRequest> {
        self.expiring_requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn surviving_heartbeats(&self) -> usize {
        self.surviving_heartbeats.load(Ordering::SeqCst)
    }
}

impl RunnerRuntimeControlClient for LeaseIsolationClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat)
                    if heartbeat.attempt_id() == self.expiring_lease.attempt_id() =>
                {
                    self.expiring_requests
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(observe(request));
                    self.clock.set_monotonic(2_000);
                    return Err(retryable_unavailable());
                }
                RunnerToServer::Heartbeat(heartbeat)
                    if heartbeat.attempt_id() == self.surviving_lease.attempt_id() =>
                {
                    self.surviving_heartbeats.fetch_add(1, Ordering::SeqCst);
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        self.surviving_lease.attempt_id(),
                        self.surviving_lease.guard(),
                        UnixMillis::new(50_000),
                    ))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Clone, Debug)]
pub struct LogBatchObservation {
    pub request: ObservedRequest,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub frame_count: usize,
    pub observed_at: u64,
}

#[derive(Debug, Default)]
struct ActiveBacklogState {
    log_batches: Vec<LogBatchObservation>,
    heartbeats: Vec<u64>,
}

#[derive(Debug)]
pub struct ActiveBacklogClient {
    session_id: automata_ci_core::RunnerSessionId,
    lease: Lease,
    sleeper: Arc<ManualDeadlineSleeper>,
    limits: automata_ci_protocol::ProtocolLimits,
    state: Mutex<ActiveBacklogState>,
    changed: tokio::sync::Notify,
}

impl ActiveBacklogClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        lease: Lease,
        sleeper: Arc<ManualDeadlineSleeper>,
    ) -> Self {
        Self {
            session_id,
            lease,
            sleeper,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            state: Mutex::new(ActiveBacklogState::default()),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub async fn wait_for_log_batches(&self, minimum: usize) {
        loop {
            let changed = self.changed.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .log_batches
                .len()
                >= minimum
            {
                return;
            }
            changed.await;
        }
    }

    pub fn log_batches(&self) -> Vec<LogBatchObservation> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .log_batches
            .clone()
    }

    pub fn heartbeats(&self) -> Vec<u64> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .heartbeats
            .clone()
    }
}

impl RunnerRuntimeControlClient for ActiveBacklogClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 10_000, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    assert_eq!(heartbeat.attempt_id(), self.lease.attempt_id());
                    let now = self.sleeper.monotonic_now().get();
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .heartbeats
                        .push(now);
                    self.changed.notify_waiters();
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        self.lease.attempt_id(),
                        self.lease.guard(),
                        UnixMillis::new(100_000),
                    ))
                }
                RunnerToServer::LogBatch(batch) => {
                    let now = self.sleeper.advance(4_000);
                    let first = batch.frames().first().expect("nonempty log batch");
                    let last = batch.frames().last().expect("nonempty log batch");
                    assert_eq!(first.attempt_id(), self.lease.attempt_id());
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .log_batches
                        .push(LogBatchObservation {
                            request: observe(request),
                            first_sequence: first.sequence().get(),
                            last_sequence: last.sequence().get(),
                            frame_count: batch.frames().len(),
                            observed_at: now,
                        });
                    self.changed.notify_waiters();
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        LogAck::new(last.stream_id(), Some(last.sequence())),
                    ))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug, Default)]
struct LogSegmentRaceClientState {
    log_batches: Vec<(u64, u64)>,
    first_ack_returned: bool,
}

#[derive(Debug)]
pub struct LogSegmentRaceClient {
    session_id: automata_ci_core::RunnerSessionId,
    lease: Lease,
    limits: automata_ci_protocol::ProtocolLimits,
    first_ack_release: CancellationToken,
    state: Mutex<LogSegmentRaceClientState>,
    changed: tokio::sync::Notify,
}

impl LogSegmentRaceClient {
    pub fn new(session_id: automata_ci_core::RunnerSessionId, lease: Lease) -> Self {
        Self {
            session_id,
            lease,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            first_ack_release: CancellationToken::new(),
            state: Mutex::new(LogSegmentRaceClientState::default()),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub async fn wait_for_log_batches(&self, minimum: usize) {
        self.wait_until(|state| state.log_batches.len() >= minimum)
            .await;
    }

    pub fn release_first_ack(&self) {
        self.first_ack_release.cancel();
    }

    pub async fn wait_for_first_ack_returned(&self) {
        self.wait_until(|state| state.first_ack_returned).await;
    }

    pub fn log_batches(&self) -> Vec<(u64, u64)> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .log_batches
            .clone()
    }

    async fn wait_until(&self, predicate: impl Fn(&LogSegmentRaceClientState) -> bool) {
        loop {
            let changed = self.changed.notified();
            if predicate(&self.state.lock().unwrap_or_else(PoisonError::into_inner)) {
                return;
            }
            changed.await;
        }
    }
}

impl RunnerRuntimeControlClient for LogSegmentRaceClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 10_000, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    assert_eq!(heartbeat.attempt_id(), self.lease.attempt_id());
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        self.lease.attempt_id(),
                        self.lease.guard(),
                        UnixMillis::new(100_000),
                    ))
                }
                RunnerToServer::LogBatch(batch) => {
                    let first = batch.frames().first().expect("nonempty race log batch");
                    let last = batch.frames().last().expect("nonempty race log batch");
                    let index = {
                        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                        state
                            .log_batches
                            .push((first.sequence().get(), last.sequence().get()));
                        let index = state.log_batches.len() - 1;
                        self.changed.notify_waiters();
                        index
                    };
                    match index {
                        0 => {
                            tokio::select! {
                                biased;
                                () = self.first_ack_release.cancelled() => {}
                                () = cancellation.cancelled() => return Err(RuntimeControlError::new(
                                    RuntimeControlErrorKind::Cancelled,
                                    RuntimeControlRetry::Never,
                                )),
                            }
                        }
                        1 => {
                            cancellation.cancelled().await;
                            return Err(RuntimeControlError::new(
                                RuntimeControlErrorKind::Cancelled,
                                RuntimeControlRetry::Never,
                            ));
                        }
                        _ => return Err(invalid_control_response()),
                    }
                    let reply = control_reply(
                        ServerToRunner::LogAck(LogAckMessage::new(
                            reply_header(batch.header()),
                            LogAck::new(last.stream_id(), Some(last.sequence())),
                        )),
                        &self.limits,
                    )?;
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .first_ack_returned = true;
                    self.changed.notify_waiters();
                    return Ok(reply);
                }
                RunnerToServer::LeaseRequest(poll) => {
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug)]
struct BlockedLogState {
    retry_failures_remaining: usize,
    blocked_requests: Vec<ObservedRequest>,
    heartbeats: Vec<(AttemptId, u64)>,
}

#[derive(Debug)]
pub struct BlockedLogClient {
    session_id: automata_ci_core::RunnerSessionId,
    leases: Vec<Lease>,
    blocked_attempt: AttemptId,
    sleeper: Arc<ManualDeadlineSleeper>,
    limits: automata_ci_protocol::ProtocolLimits,
    state: Mutex<BlockedLogState>,
    changed: tokio::sync::Notify,
}

impl BlockedLogClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        leases: Vec<Lease>,
        blocked_attempt: AttemptId,
        sleeper: Arc<ManualDeadlineSleeper>,
        retry_failures: usize,
    ) -> Self {
        Self {
            session_id,
            leases,
            blocked_attempt,
            sleeper,
            limits: automata_ci_protocol::ProtocolLimits::default(),
            state: Mutex::new(BlockedLogState {
                retry_failures_remaining: retry_failures,
                blocked_requests: Vec::new(),
                heartbeats: Vec::new(),
            }),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub async fn wait_for_blocked_requests(&self, minimum: usize) {
        loop {
            let changed = self.changed.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .blocked_requests
                .len()
                >= minimum
            {
                return;
            }
            changed.await;
        }
    }

    pub async fn wait_for_heartbeats(&self, attempt_id: AttemptId, minimum: usize) {
        loop {
            let changed = self.changed.notified();
            let count = self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .heartbeats
                .iter()
                .filter(|(observed, _)| *observed == attempt_id)
                .count();
            if count >= minimum {
                return;
            }
            changed.await;
        }
    }

    pub fn blocked_requests(&self) -> Vec<ObservedRequest> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .blocked_requests
            .clone()
    }

    pub fn heartbeat_times(&self, attempt_id: AttemptId) -> Vec<u64> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .heartbeats
            .iter()
            .filter_map(|(observed, at)| (*observed == attempt_id).then_some(*at))
            .collect()
    }
}

impl RunnerRuntimeControlClient for BlockedLogClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 5_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    let lease = self
                        .leases
                        .iter()
                        .find(|lease| lease.attempt_id() == heartbeat.attempt_id())
                        .expect("heartbeat for configured lease");
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .heartbeats
                        .push((heartbeat.attempt_id(), self.sleeper.monotonic_now().get()));
                    self.changed.notify_waiters();
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        lease.attempt_id(),
                        lease.guard(),
                        UnixMillis::new(100_000),
                    ))
                }
                RunnerToServer::LogBatch(batch) => {
                    let last = batch.frames().last().expect("nonempty log batch");
                    if last.attempt_id() == self.blocked_attempt {
                        let retry = {
                            let mut state =
                                self.state.lock().unwrap_or_else(PoisonError::into_inner);
                            state.blocked_requests.push(observe(request));
                            let retry = state.retry_failures_remaining > 0;
                            state.retry_failures_remaining =
                                state.retry_failures_remaining.saturating_sub(1);
                            retry
                        };
                        self.changed.notify_waiters();
                        if retry {
                            return Err(retryable_unavailable());
                        }
                        cancellation.cancelled().await;
                        return Err(RuntimeControlError::new(
                            RuntimeControlErrorKind::Cancelled,
                            RuntimeControlRetry::Never,
                        ));
                    }
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        LogAck::new(last.stream_id(), Some(last.sequence())),
                    ))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug)]
struct SlowLogState {
    log_batches: Vec<LogBatchObservation>,
    heartbeats: Vec<(JobLifecycle, u64, UnixMillis)>,
    last_heartbeat_at: u64,
    retried_first_batch: bool,
    starved: bool,
}

#[derive(Debug)]
pub struct SlowLogClient {
    session_id: automata_ci_core::RunnerSessionId,
    lease: Lease,
    clock: Arc<ManualClock>,
    lease_clock_anchor: u64,
    shutdown: CancellationToken,
    stop_on_first_batch: bool,
    retry_first_batch: bool,
    log_delay: Duration,
    limits: automata_ci_protocol::ProtocolLimits,
    state: Mutex<SlowLogState>,
}

impl SlowLogClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        lease: Lease,
        clock: Arc<ManualClock>,
        shutdown: CancellationToken,
        stop_on_first_batch: bool,
        retry_first_batch: bool,
    ) -> Self {
        let lease_clock_anchor = clock.monotonic_now().get();
        Self {
            session_id,
            lease,
            clock,
            lease_clock_anchor,
            shutdown,
            stop_on_first_batch,
            retry_first_batch,
            log_delay: Duration::from_millis(3),
            limits: automata_ci_protocol::ProtocolLimits::default(),
            state: Mutex::new(SlowLogState {
                log_batches: Vec::new(),
                heartbeats: Vec::new(),
                last_heartbeat_at: lease_clock_anchor,
                retried_first_batch: false,
                starved: false,
            }),
        }
    }

    pub fn log_batches(&self) -> Vec<LogBatchObservation> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .log_batches
            .clone()
    }

    pub fn heartbeats(&self) -> Vec<(JobLifecycle, u64, UnixMillis)> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .heartbeats
            .clone()
    }

    pub const fn lease_clock_anchor(&self) -> u64 {
        self.lease_clock_anchor
    }

    pub fn starved(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .starved
    }
}

impl RunnerRuntimeControlClient for SlowLogClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovery hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1, 30_000),
                    ))
                }
                RunnerToServer::LeaseResponse(response)
                    if response.disposition()
                        == &automata_ci_protocol::LeaseDisposition::Accepted =>
                {
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(response.header())))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    let now = self.clock.monotonic_now().get();
                    let elapsed = now.saturating_sub(self.lease_clock_anchor);
                    let renewal_expiry =
                        50_000_i64.saturating_add(i64::try_from(elapsed).unwrap_or(i64::MAX));
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    state.last_heartbeat_at = now;
                    state.heartbeats.push((
                        heartbeat.lifecycle(),
                        now,
                        UnixMillis::new(renewal_expiry),
                    ));
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        self.lease.attempt_id(),
                        self.lease.guard(),
                        UnixMillis::new(renewal_expiry),
                    ))
                }
                RunnerToServer::LogBatch(batch) => {
                    tokio::time::sleep(self.log_delay).await;
                    let now = self.clock.advance_monotonic(8_000);
                    let first = batch.frames().first().expect("nonempty log batch");
                    let last = batch.frames().last().expect("nonempty log batch");
                    let retry = {
                        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                        if now.saturating_sub(state.last_heartbeat_at) >= 30_000 {
                            state.starved = true;
                            return Err(invalid_control_response());
                        }
                        state.log_batches.push(LogBatchObservation {
                            request: observe(request),
                            first_sequence: first.sequence().get(),
                            last_sequence: last.sequence().get(),
                            frame_count: batch.frames().len(),
                            observed_at: now,
                        });
                        if self.stop_on_first_batch && state.log_batches.len() == 1 {
                            self.shutdown.cancel();
                            return Err(retryable_unavailable());
                        }
                        if self.retry_first_batch && !state.retried_first_batch {
                            state.retried_first_batch = true;
                            true
                        } else {
                            false
                        }
                    };
                    if retry {
                        return Err(retryable_unavailable());
                    }
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        LogAck::new(last.stream_id(), Some(last.sequence())),
                    ))
                }
                RunnerToServer::JobResult(result) => {
                    self.shutdown.cancel();
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(result.header())))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

#[derive(Debug, Default)]
struct RecoveredFinalizationState {
    heartbeats: Vec<u64>,
    log_started: bool,
    log_acknowledged: bool,
}

#[derive(Debug)]
pub struct RecoveredFinalizationClient {
    session_id: automata_ci_core::RunnerSessionId,
    lease: Lease,
    sleeper: Arc<ManualDeadlineSleeper>,
    shutdown: CancellationToken,
    log_release: CancellationToken,
    limits: automata_ci_protocol::ProtocolLimits,
    state: Mutex<RecoveredFinalizationState>,
    changed: tokio::sync::Notify,
}

impl RecoveredFinalizationClient {
    pub fn new(
        session_id: automata_ci_core::RunnerSessionId,
        lease: Lease,
        sleeper: Arc<ManualDeadlineSleeper>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            session_id,
            lease,
            sleeper,
            shutdown,
            log_release: CancellationToken::new(),
            limits: automata_ci_protocol::ProtocolLimits::default(),
            state: Mutex::new(RecoveredFinalizationState::default()),
            changed: tokio::sync::Notify::new(),
        }
    }

    pub async fn wait_for_heartbeats(&self, minimum: usize) {
        self.wait_until(|state| state.heartbeats.len() >= minimum)
            .await;
    }

    pub async fn wait_for_log_delivery(&self) {
        self.wait_until(|state| state.log_started).await;
    }

    pub fn heartbeat_times(&self) -> Vec<u64> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .heartbeats
            .clone()
    }

    pub fn release_log_delivery(&self) {
        self.log_release.cancel();
    }

    async fn wait_until(&self, predicate: impl Fn(&RecoveredFinalizationState) -> bool) {
        loop {
            let changed = self.changed.notified();
            if predicate(&self.state.lock().unwrap_or_else(PoisonError::into_inner)) {
                return;
            }
            changed.await;
        }
    }
}

impl RunnerRuntimeControlClient for RecoveredFinalizationClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        Box::pin(async move {
            let response = match request.message() {
                RunnerToServer::Hello(hello) => {
                    let resume = hello.resume().expect("recovered finalization hello");
                    ServerToRunner::Hello(ServerHello::new(
                        OperationId::new(),
                        hello.operation_id(),
                        NegotiatedSession::new(
                            SUPPORTED_PROTOCOL_RANGE.max(),
                            automata_ci_core::JobIrVersion::current(),
                            self.session_id,
                            SessionDisposition::Resumed,
                            resume.command_cursor(),
                        ),
                        ServerTiming::new(UnixMillis::new(10_000), 1_000, 30_000),
                    ))
                }
                RunnerToServer::Heartbeat(heartbeat) => {
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .heartbeats
                        .push(self.sleeper.monotonic_now().get());
                    self.changed.notify_waiters();
                    ServerToRunner::LeaseRenewal(LeaseRenewal::new(
                        reply_header(heartbeat.header()),
                        self.lease.attempt_id(),
                        self.lease.guard(),
                        UnixMillis::new(40_000),
                    ))
                }
                RunnerToServer::LogBatch(batch) => {
                    {
                        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                        state.log_started = true;
                        self.changed.notify_waiters();
                    }
                    tokio::select! {
                        biased;
                        () = self.log_release.cancelled() => {}
                        () = cancellation.cancelled() => return Err(RuntimeControlError::new(
                            RuntimeControlErrorKind::Cancelled,
                            RuntimeControlRetry::Never,
                        )),
                    }
                    let last = batch.frames().last().expect("runtime EOS batch");
                    self.state
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .log_acknowledged = true;
                    ServerToRunner::LogAck(LogAckMessage::new(
                        reply_header(batch.header()),
                        LogAck::new(last.stream_id(), Some(last.sequence())),
                    ))
                }
                RunnerToServer::JobResult(result) => {
                    assert!(
                        self.state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .log_acknowledged,
                        "terminal result follows EOS acknowledgement"
                    );
                    ServerToRunner::OperationAck(OperationAck::new(reply_header(result.header())))
                }
                RunnerToServer::LeaseRequest(poll) => {
                    self.shutdown.cancel();
                    ServerToRunner::NoWork(NoWork::new(reply_header(poll.header()), 1))
                }
                _ => return Err(invalid_control_response()),
            };
            control_reply(response, &self.limits)
        })
    }
}

pub struct AcceptedFixture {
    pub session_id: automata_ci_core::RunnerSessionId,
    pub slot: RunnerSlotOrdinal,
    pub lease: Lease,
}

pub fn seed_accepted_offer(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    runner_id: RunnerId,
) -> AcceptedFixture {
    let fixture = seed_recorded_offer(journal, spool, runner_id);
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept offer locally");
    fixture
}

pub fn seed_accepted_credential_free_offer(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    runner_id: RunnerId,
) -> AcceptedFixture {
    let session_id = automata_ci_core::RunnerSessionId::new();
    let slot = RunnerSlotOrdinal::new(1).expect("slot one");
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(7).expect("fence"),
        UnixMillis::new(9_000),
        UnixMillis::new(40_000),
    )
    .expect("lease");
    journal
        .begin_session(SessionBinding::new(
            session_id,
            SUPPORTED_PROTOCOL_RANGE.max(),
            automata_ci_core::JobIrVersion::current(),
        ))
        .expect("begin session");
    let job = credential_free_job();
    let authorities =
        JobRuntimeAuthorities::new(Vec::new(), &job, &lease).expect("empty authority bundle");
    record_test_offer_with_authorities(
        journal,
        spool,
        session_id,
        slot,
        &lease,
        &job,
        &authorities,
        DurableCommand::new(
            CommandSequence::new(1).expect("sequence"),
            OperationId::new(),
            Sha256Digest::from_bytes([0x34; 32]),
        ),
    );
    journal
        .accept_lease(session_id, slot, lease.guard())
        .expect("accept credential-free offer locally");
    AcceptedFixture {
        session_id,
        slot,
        lease,
    }
}

pub fn seed_accepted_offer_expiring_at(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    runner_id: RunnerId,
    expires_at: i64,
) -> AcceptedFixture {
    let fixture = seed_recorded_offer_expiring_at(journal, spool, runner_id, expires_at);
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept short offer locally");
    fixture
}

pub fn seed_accepted_offer_with_authority_expiries(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    runner_id: RunnerId,
    lease_expires_at: i64,
    authority_expires_at: &[i64],
) -> AcceptedFixture {
    let fixture = seed_recorded_offer_with_authority_expiries(
        journal,
        spool,
        runner_id,
        lease_expires_at,
        authority_expires_at,
    );
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept authority-bounded offer locally");
    fixture
}

pub fn seed_failed_terminal_without_logs(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    fixture: &AcceptedFixture,
) {
    let guard = fixture.lease.guard();
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Preparing,
        )
        .expect("seed recovered preparing lifecycle");

    let operation_id = OperationId::new();
    let result = JobResult::new(
        fixture.lease.attempt_id(),
        JobConclusion::Failure,
        JobSecretExposure::Secretless,
        UnixMillis::new(9_900),
    );
    let negotiated = NegotiatedSession::new(
        SUPPORTED_PROTOCOL_RANGE.max(),
        automata_ci_core::JobIrVersion::current(),
        fixture.session_id,
        SessionDisposition::Resumed,
        CommandCursor::through(CommandSequence::new(1).expect("first command")),
    );
    let message = RunnerToServer::JobResult(JobResultMessage::new(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            fixture.session_id,
            operation_id,
        ),
        guard,
        result,
    ));
    let prepared = PreparedRequest::for_session(
        message,
        negotiated,
        &automata_ci_protocol::ProtocolLimits::default(),
    )
    .expect("prepare recovered terminal result");
    let publication = spool
        .persist(ContentKind::TerminalResult, prepared.canonical_bytes())
        .expect("persist recovered terminal result");
    let committed = publication.commit_with(|content| {
        journal.record_terminal_result(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Failed,
            TerminalResultRecord::new(operation_id, content.clone())?,
            UnixMillis::new(9_900),
        )
    });
    assert!(committed.is_ok(), "adopt recovered terminal result");
}

pub fn seed_additional_accepted_offer(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    runner_id: RunnerId,
    session_id: automata_ci_core::RunnerSessionId,
    ordinal: u16,
    sequence: u64,
) -> AcceptedFixture {
    let slot = RunnerSlotOrdinal::new(ordinal).expect("additional slot");
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(u64::from(ordinal) + 7).expect("fence"),
        UnixMillis::new(9_000),
        UnixMillis::new(40_000),
    )
    .expect("lease");
    let job = minimal_job();
    record_test_offer(
        journal,
        spool,
        session_id,
        slot,
        &lease,
        &job,
        DurableCommand::new(
            CommandSequence::new(sequence).expect("command sequence"),
            OperationId::new(),
            Sha256Digest::from_bytes([u8::try_from(ordinal).unwrap_or(u8::MAX); 32]),
        ),
    );
    journal
        .accept_lease(session_id, slot, lease.guard())
        .expect("accept additional offer locally");
    AcceptedFixture {
        session_id,
        slot,
        lease,
    }
}

pub fn seed_recorded_offer(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    runner_id: RunnerId,
) -> AcceptedFixture {
    seed_recorded_offer_expiring_at(journal, spool, runner_id, 40_000)
}

fn seed_recorded_offer_expiring_at(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    runner_id: RunnerId,
    expires_at: i64,
) -> AcceptedFixture {
    seed_recorded_offer_with_authority_expiries(journal, spool, runner_id, expires_at, &[60_000])
}

fn seed_recorded_offer_with_authority_expiries(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    runner_id: RunnerId,
    lease_expires_at: i64,
    authority_expires_at: &[i64],
) -> AcceptedFixture {
    let session_id = automata_ci_core::RunnerSessionId::new();
    let slot = RunnerSlotOrdinal::new(1).expect("slot one");
    let lease = Lease::new(
        LeaseId::new(),
        AttemptId::new(),
        runner_id,
        FencingToken::new(7).expect("fence"),
        UnixMillis::new(9_000),
        UnixMillis::new(lease_expires_at),
    )
    .expect("lease");
    journal
        .begin_session(SessionBinding::new(
            session_id,
            SUPPORTED_PROTOCOL_RANGE.max(),
            automata_ci_core::JobIrVersion::current(),
        ))
        .expect("begin session");
    let job = minimal_job();
    let authorities = test_runtime_authorities_with_expiries(&job, &lease, authority_expires_at);
    record_test_offer_with_authorities(
        journal,
        spool,
        session_id,
        slot,
        &lease,
        &job,
        &authorities,
        DurableCommand::new(
            CommandSequence::new(1).expect("sequence"),
            OperationId::new(),
            Sha256Digest::from_bytes([0x33; 32]),
        ),
    );
    AcceptedFixture {
        session_id,
        slot,
        lease,
    }
}

#[allow(clippy::too_many_arguments)]
fn record_test_offer(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    session_id: automata_ci_core::RunnerSessionId,
    slot: RunnerSlotOrdinal,
    lease: &Lease,
    job: &JobIrEnvelope,
    command: DurableCommand,
) {
    let authorities = test_runtime_authorities(job, lease);
    record_test_offer_with_authorities(
        journal,
        spool,
        session_id,
        slot,
        lease,
        job,
        &authorities,
        command,
    );
}

#[allow(clippy::too_many_arguments)]
fn record_test_offer_with_authorities(
    journal: &dyn RunnerJournal,
    spool: &dyn DurableContentStore,
    session_id: automata_ci_core::RunnerSessionId,
    slot: RunnerSlotOrdinal,
    lease: &Lease,
    job: &JobIrEnvelope,
    authorities: &JobRuntimeAuthorities,
    command: DurableCommand,
) {
    let limits = automata_ci_protocol::ProtocolLimits::default();
    let encoded_job = encode_job_ir(job, &limits).expect("encode JobIR");
    let encoded_authorities = Zeroizing::new(
        encode_runtime_authorities(authorities, job, lease, &limits)
            .expect("encode runtime authorities"),
    );
    let job_publication = spool
        .persist(ContentKind::JobIr, &encoded_job)
        .expect("persist JobIR");
    let adopted = job_publication.commit_with(|job_content| {
        let authority_publication = spool
            .persist(ContentKind::RuntimeAuthority, &encoded_authorities)
            .expect("persist runtime authorities");
        let authority_adopted = authority_publication.commit_with(|authority_content| {
            let job_reference = JobIrContentRef::new(job.version(), job_content.clone())?;
            let authority_reference = RuntimeAuthorityContentRef::new(authority_content.clone())?;
            let offer = LeaseOfferRecord::new(
                slot,
                lease.clone(),
                job_reference,
                authority_reference,
                command,
            )?;
            journal.record_lease_offer(session_id, offer)
        });
        match authority_adopted {
            Ok(snapshot) => Ok(snapshot),
            Err(failure) => {
                let (error, publication) = failure.into_parts();
                publication.abort();
                Err(error)
            }
        }
    });
    if let Err(failure) = adopted {
        let (error, publication) = failure.into_parts();
        publication.abort();
        panic!("journal test offer: {error}");
    }
}

pub fn test_runtime_authorities(job: &JobIrEnvelope, lease: &Lease) -> JobRuntimeAuthorities {
    test_runtime_authorities_with_expiries(job, lease, &[60_000])
}

fn test_runtime_authorities_with_expiries(
    job: &JobIrEnvelope,
    lease: &Lease,
    expiries: &[i64],
) -> JobRuntimeAuthorities {
    JobRuntimeAuthorities::new(
        expiries
            .iter()
            .enumerate()
            .map(|(index, expires_at)| {
                let name = if expiries.len() == 1 {
                    "github.actions.results".to_owned()
                } else {
                    format!("github.actions.results.{index:04}")
                };
                JobRuntimeAuthority::new(
                    RuntimeAuthorityName::new(name).expect("authority name"),
                    job.job().run_id(),
                    job.job().job_id(),
                    lease.attempt_id(),
                    lease.fencing_token(),
                    RuntimeAuthorityEndpoint::loopback_development("http://127.0.0.1:8080/")
                        .expect("authority endpoint"),
                    RuntimeAuthorityCredential::new("runtime-test-credential")
                        .expect("authority credential"),
                    UnixMillis::new(9_000),
                    UnixMillis::new(*expires_at),
                )
                .expect("runtime authority")
            })
            .collect(),
        job,
        lease,
    )
    .expect("runtime authority bundle")
}

pub fn minimal_job() -> JobIrEnvelope {
    minimal_job_with_profile(JobAuthorityProfile::Standard)
}

pub fn credential_free_job() -> JobIrEnvelope {
    minimal_job_with_profile(JobAuthorityProfile::CredentialFree)
}

fn minimal_job_with_profile(authority_profile: JobAuthorityProfile) -> JobIrEnvelope {
    let requirements = RunnerRequirements::default().with_environment_profile(environment());
    let step = StepIr::new(
        StepId::new("verify").expect("step ID"),
        ValueTemplate::literal("verify").expect("literal step name"),
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("true").expect("literal command"),
            ShellTemplate::default_shell(),
        )),
    );
    JobIrEnvelope::new(
        WorkflowId::new(),
        JobSource::new(
            "github",
            "automata-ci/automata",
            "0123456789abcdef0123456789abcdef01234567",
            ".ci/workflows/ci.yml",
            "push",
        ),
        automata_ci_core::JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/__w/automata/automata",
            automata_ci_core::JobContentReference::new(
                "events/push.json",
                automata_ci_core::Sha256Digest::from_bytes([0x42; 32]),
                2,
                "application/json",
            ),
            automata_ci_core::JobContentReference::new(
                "contexts/runtime.pb",
                automata_ci_core::Sha256Digest::from_bytes([0x43; 32]),
                2,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
        ),
        JobIr::new(
            JobId::new(),
            RunId::new(),
            "verify",
            requirements,
            JobInstanceIdentity::new("verify", 0, 1, Sha256Digest::from_bytes([0x44; 32]))
                .expect("job instance"),
            false,
            vec![step],
        )
        .with_authority_profile(authority_profile)
        .with_permission_request(match authority_profile {
            JobAuthorityProfile::Standard => JobPermissionRequest::ProviderDefault,
            JobAuthorityProfile::CredentialFree => JobPermissionRequest::Mapping(Vec::new()),
        }),
    )
}

fn reply_header(request: MessageHeader) -> MessageHeader {
    MessageHeader::reply(
        request.protocol_version(),
        request.session_id(),
        OperationId::new(),
        request.operation_id(),
    )
}

fn observe(request: &PreparedRequest) -> ObservedRequest {
    ObservedRequest {
        operation_id: request.operation_id(),
        canonical_bytes: request.canonical_bytes().to_vec(),
        address: std::ptr::from_ref(request) as usize,
        is_hello: matches!(request.message(), RunnerToServer::Hello(_)),
        resume: None,
    }
}

fn retryable_unavailable() -> RuntimeControlError {
    RuntimeControlError::new(
        RuntimeControlErrorKind::Unavailable,
        RuntimeControlRetry::SamePreparedRequest,
    )
}

fn invalid_control_response() -> RuntimeControlError {
    RuntimeControlError::new(
        RuntimeControlErrorKind::InvalidResponse,
        RuntimeControlRetry::Never,
    )
}

fn control_reply(
    message: ServerToRunner,
    limits: &automata_ci_protocol::ProtocolLimits,
) -> Result<RuntimeControlReply, RuntimeControlError> {
    RuntimeControlReply::from_message(message, limits).map_err(|_| invalid_control_response())
}

pub fn config(runner_id: RunnerId) -> RunnerRuntimeConfig {
    config_with_retry(runner_id, RetryPolicy::default())
}

pub fn config_with_retry(runner_id: RunnerId, retry: RetryPolicy) -> RunnerRuntimeConfig {
    config_with_slots_and_retry(runner_id, 1, retry)
}

pub fn config_with_slots_and_retry(
    runner_id: RunnerId,
    slots: u16,
    retry: RetryPolicy,
) -> RunnerRuntimeConfig {
    let limits = RunnerRuntimeLimits::new(
        retry,
        Duration::from_millis(25),
        Duration::from_mins(5),
        Duration::from_millis(100),
        Duration::from_secs(30),
    )
    .expect("runtime limits");
    RunnerRuntimeConfig::new(
        capabilities(runner_id, slots),
        automata_ci_protocol::ProtocolLimits::default(),
        limits,
    )
    .expect("runtime config")
}

pub fn config_with_cancellation_grace(
    runner_id: RunnerId,
    cancellation_grace: Duration,
) -> RunnerRuntimeConfig {
    let limits = RunnerRuntimeLimits::new(
        RetryPolicy::default(),
        Duration::from_millis(25),
        Duration::from_mins(5),
        Duration::from_millis(100),
        cancellation_grace,
    )
    .expect("runtime limits with custom cancellation grace");
    RunnerRuntimeConfig::new(
        capabilities(runner_id, 1),
        automata_ci_protocol::ProtocolLimits::default(),
        limits,
    )
    .expect("runtime config with custom cancellation grace")
}

pub fn assert_session(journal: &dyn RunnerJournal, expected: automata_ci_core::RunnerSessionId) {
    assert_eq!(
        journal
            .snapshot()
            .expect("journal snapshot")
            .session()
            .expect("durable session")
            .session_id(),
        expected,
    );
}
