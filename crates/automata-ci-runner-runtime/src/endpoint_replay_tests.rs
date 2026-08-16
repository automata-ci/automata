use std::{
    fmt, fs,
    num::NonZeroU16,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_core::{
    AttemptId, EnvironmentProfile, EnvironmentProfileId, FencingToken, JobIrVersion, Lease,
    LeaseId, OperationId, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_ci_execution::{
    Cancellation, CancellationDisposition, CopyFromRequest, CopyToRequest, DestroyDisposition,
    DestroySandbox, EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionArgv,
    ExecutionCommand, ExecutionEndpoint, ExecutionEnvironment, ExecutionError, ExecutionErrorKind,
    ExecutionOutput, ExecutionStage, ProviderCapabilities, ProviderError, ProviderErrorKind,
    ProviderId, ProviderStage, SandboxCapability, SandboxCustody, SandboxGeneration, SandboxHandle,
    SandboxInspection, SandboxProvider, SandboxRecord, SandboxSpec, SandboxState, SignalRequest,
    TargetPath, WaitRequest,
};
use automata_ci_protocol::{
    CommandSequence, PROTOCOL_MAX_VERSION, RunnerSlotOrdinal, RuntimeAuthorityDeliveryBinding,
    RuntimeAuthorityGeneration,
};
use automata_ci_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, ContentKind, DurableCommand, DurableContentRef,
    EndpointOperationState, FileJournal, FileJournalOptions, JobIrContentRef, LeaseOfferRecord,
    ProviderName, ProviderOperation, ProviderOperationKind, RunnerJournal,
    RuntimeAuthorityContentRef, RuntimeAuthorityDeliveryRecord,
    SandboxHandle as JournalSandboxHandle, SandboxIdentity, SessionBinding, StateRoot,
};
use automata_ci_runner_spool::{
    ContentCommitFault, ContentCommitFaultInjector, ContentCommitStage, ContentCommitmentDomain,
    ContentProtectionError, ContentProtector, FileSpool, FileSpoolOptions, ProtectionId,
    SpoolLimits, SpoolRoot, endpoint_result_allocation,
};
use sha2::{Digest as _, Sha256};

use crate::{content::ContentOperationCoordinator, endpoint_replay::DurableExecutionEndpoint};

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/agent-scratch/endpoint-replay-tests")
            .join(format!("{label}-{}", OperationId::new()));
        fs::create_dir_all(&path).expect("create test scratch");
        Self(fs::canonicalize(path).expect("canonical test scratch"))
    }

    fn child(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestProtector {
    id: ProtectionId,
    key: [u8; 32],
}

impl TestProtector {
    fn new() -> Self {
        Self {
            id: ProtectionId::new("endpoint-replay-test-v1").expect("protection id"),
            key: [0x7c; 32],
        }
    }

    fn tag(&self, reference: &DurableContentRef, bytes: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.key);
        digest.update(reference.cache_key().as_str().as_bytes());
        digest.update(bytes);
        digest.finalize().into()
    }
}

impl fmt::Debug for TestProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("TestProtector").finish()
    }
}

impl ContentProtector for TestProtector {
    fn protection_id(&self) -> &ProtectionId {
        &self.id
    }

    fn keyed_commitment(
        &self,
        protection_id: &ProtectionId,
        domain: ContentCommitmentDomain,
        material_digest: &[u8; 32],
    ) -> Result<[u8; 32], ContentProtectionError> {
        if protection_id != &self.id {
            return Err(ContentProtectionError::KeyUnavailable);
        }
        let mut digest = Sha256::new();
        digest.update(self.key);
        digest.update(domain.separator());
        digest.update(material_digest);
        Ok(digest.finalize().into())
    }

    fn endpoint_result_protected_bytes(
        &self,
        plaintext_bytes: u64,
    ) -> Result<u64, ContentProtectionError> {
        endpoint_result_allocation(plaintext_bytes).map_err(|_| ContentProtectionError::Failed)
    }

    fn protect(
        &self,
        reference: &DurableContentRef,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        let mut protected = if let Some(allocation) = reference.endpoint_result_allocation_bytes() {
            let allocation =
                usize::try_from(allocation).map_err(|_| ContentProtectionError::Failed)?;
            let body_bytes = allocation
                .checked_sub(32)
                .ok_or(ContentProtectionError::Failed)?;
            let required = 8_usize
                .checked_add(plaintext.len())
                .ok_or(ContentProtectionError::Failed)?;
            if required > body_bytes {
                return Err(ContentProtectionError::Failed);
            }
            let mut body = Vec::with_capacity(allocation);
            body.extend_from_slice(
                &u64::try_from(plaintext.len())
                    .map_err(|_| ContentProtectionError::Failed)?
                    .to_be_bytes(),
            );
            body.extend(plaintext.iter().map(|byte| byte ^ 0xa5));
            body.resize(body_bytes, 0);
            body
        } else {
            plaintext.iter().map(|byte| byte ^ 0xa5).collect()
        };
        protected.extend_from_slice(&self.tag(reference, &protected));
        Ok(protected)
    }

    fn unprotect(
        &self,
        reference: &DurableContentRef,
        protected: &[u8],
    ) -> Result<Vec<u8>, ContentProtectionError> {
        let split = protected
            .len()
            .checked_sub(32)
            .ok_or(ContentProtectionError::AuthenticationFailed)?;
        let (ciphertext, tag) = protected.split_at(split);
        if tag != self.tag(reference, ciphertext) {
            return Err(ContentProtectionError::AuthenticationFailed);
        }
        if reference.endpoint_result_allocation_bytes().is_some() {
            let length = ciphertext
                .get(..8)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_be_bytes)
                .and_then(|bytes| usize::try_from(bytes).ok())
                .ok_or(ContentProtectionError::AuthenticationFailed)?;
            let end = 8_usize
                .checked_add(length)
                .filter(|end| *end <= ciphertext.len())
                .ok_or(ContentProtectionError::AuthenticationFailed)?;
            if ciphertext[end..].iter().any(|byte| *byte != 0) {
                return Err(ContentProtectionError::AuthenticationFailed);
            }
            return Ok(ciphertext[8..end].iter().map(|byte| byte ^ 0xa5).collect());
        }
        Ok(ciphertext.iter().map(|byte| byte ^ 0xa5).collect())
    }
}

#[derive(Debug)]
struct ArmedJournalFault {
    stage: CommitStage,
    matching_commits_to_skip: usize,
}

#[derive(Debug, Default)]
struct ArmableJournalFault(Mutex<Option<ArmedJournalFault>>);

impl ArmableJournalFault {
    fn arm(&self, stage: CommitStage) {
        self.arm_after(stage, 0);
    }

    fn arm_after(&self, stage: CommitStage, matching_commits_to_skip: usize) {
        *self.0.lock().expect("journal fault lock") = Some(ArmedJournalFault {
            stage,
            matching_commits_to_skip,
        });
    }
}

impl CommitFaultInjector for ArmableJournalFault {
    fn check(&self, stage: CommitStage) -> Result<(), CommitFault> {
        let mut armed = self.0.lock().expect("journal fault lock");
        let Some(fault) = armed.as_mut().filter(|fault| fault.stage == stage) else {
            return Ok(());
        };
        if fault.matching_commits_to_skip > 0 {
            fault.matching_commits_to_skip -= 1;
            return Ok(());
        }
        *armed = None;
        Err(CommitFault)
    }
}

#[derive(Debug)]
struct ArmedContentFault {
    stage: ContentCommitStage,
    matching_commits_to_skip: usize,
}

#[derive(Debug, Default)]
struct ArmableContentFault(Mutex<Option<ArmedContentFault>>);

impl ArmableContentFault {
    fn arm(&self, stage: ContentCommitStage) {
        self.arm_after(stage, 0);
    }

    fn arm_after(&self, stage: ContentCommitStage, matching_commits_to_skip: usize) {
        *self.0.lock().expect("content fault lock") = Some(ArmedContentFault {
            stage,
            matching_commits_to_skip,
        });
    }
}

impl ContentCommitFaultInjector for ArmableContentFault {
    fn check(&self, stage: ContentCommitStage) -> Result<(), ContentCommitFault> {
        let mut armed = self.0.lock().expect("content fault lock");
        let Some(fault) = armed.as_mut().filter(|fault| fault.stage == stage) else {
            return Ok(());
        };
        if fault.matching_commits_to_skip > 0 {
            fault.matching_commits_to_skip -= 1;
            return Ok(());
        }
        *armed = None;
        Err(ContentCommitFault)
    }
}

#[derive(Debug)]
struct FakeProvider {
    id: ProviderId,
    capabilities: ProviderCapabilities,
    inspection: Mutex<SandboxInspection>,
    inspections: AtomicUsize,
}

impl FakeProvider {
    fn new(inspection: SandboxInspection) -> Self {
        let capabilities = vec![
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::CopyFrom,
        ];
        Self {
            id: inspection.handle().provider().clone(),
            capabilities: ProviderCapabilities::new(capabilities).expect("capabilities"),
            inspection: Mutex::new(inspection),
            inspections: AtomicUsize::new(0),
        }
    }
}

impl SandboxProvider for FakeProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn create(
        &self,
        _spec: &SandboxSpec,
        _cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        Err(provider_error(ProviderStage::CreateSandbox))
    }

    fn attach(
        &self,
        _handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
        Err(provider_error(ProviderStage::Attach))
    }

    fn inspect(
        &self,
        _handle: &SandboxHandle,
        _cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        Ok(self.inspection.lock().expect("inspection lock").clone())
    }

    fn destroy(
        &self,
        _request: &DestroySandbox,
        _cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        Err(provider_error(ProviderStage::DestroySandbox))
    }
}

fn provider_error(stage: ProviderStage) -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::BackendRejected,
        stage,
        automata_ci_execution::OperationOutcome::KnownNoEffect,
        None,
    )
}

#[derive(Debug)]
struct FakeEndpoint {
    handle: SandboxHandle,
    calls: Arc<AtomicUsize>,
    terminations: Arc<AtomicUsize>,
}

impl ExecutionEndpoint for FakeEndpoint {
    fn handle(&self) -> &SandboxHandle {
        &self.handle
    }

    fn capabilities(&self) -> &[SandboxCapability] {
        const CAPABILITIES: &[SandboxCapability] = &[SandboxCapability::CopyFrom];
        CAPABILITIES
    }

    fn exec(
        &self,
        _request: &ExecutionCommand,
        _cancellation: &dyn Cancellation,
    ) -> Result<ExecutionOutput, ExecutionError> {
        Err(endpoint_error(ExecutionStage::Exec))
    }

    fn signal(
        &self,
        _request: SignalRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        Err(endpoint_error(ExecutionStage::Signal))
    }

    fn wait(
        &self,
        _request: WaitRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<i32, ExecutionError> {
        Err(endpoint_error(ExecutionStage::Wait))
    }

    fn copy_to(
        &self,
        _request: &CopyToRequest,
        _cancellation: &dyn Cancellation,
    ) -> Result<(), ExecutionError> {
        Err(endpoint_error(ExecutionStage::CopyTo))
    }

    fn copy_from(
        &self,
        _request: &CopyFromRequest,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, ExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if cancellation.disposition().requires_termination() {
            self.terminations.fetch_add(1, Ordering::SeqCst);
            Err(ExecutionError::new(
                ExecutionErrorKind::Cancelled,
                ExecutionStage::CopyFrom,
            ))
        } else {
            Ok(b"protected replay result".to_vec())
        }
    }
}

fn endpoint_error(stage: ExecutionStage) -> ExecutionError {
    ExecutionError::new(ExecutionErrorKind::UnsupportedCapability, stage)
}

#[derive(Debug)]
struct SequencedCancellation {
    observations: AtomicUsize,
    trigger_after: usize,
    disposition: CancellationDisposition,
}

impl SequencedCancellation {
    fn after(trigger_after: usize, disposition: CancellationDisposition) -> Self {
        Self {
            observations: AtomicUsize::new(0),
            trigger_after,
            disposition,
        }
    }
}

impl Cancellation for SequencedCancellation {
    fn disposition(&self) -> CancellationDisposition {
        let observation = self.observations.fetch_add(1, Ordering::SeqCst);
        if observation >= self.trigger_after {
            self.disposition
        } else {
            CancellationDisposition::Active
        }
    }
}

struct Fixture {
    scratch: Scratch,
    journal: Arc<FileJournal>,
    spool: Arc<FileSpool>,
    coordinator: Arc<ContentOperationCoordinator>,
    serial: Arc<Mutex<()>>,
    provider: Arc<FakeProvider>,
    inspection: SandboxInspection,
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
    guard: automata_ci_core::LeaseGuard,
    calls: Arc<AtomicUsize>,
    terminations: Arc<AtomicUsize>,
    journal_fault: Arc<ArmableJournalFault>,
    spool_fault: Arc<ArmableContentFault>,
}

fn record_test_runtime_authority(
    journal: &FileJournal,
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
    lease: &Lease,
    offer: &LeaseOfferRecord,
) {
    let content =
        RuntimeAuthorityContentRef::new(content_ref(ContentKind::RuntimeAuthority, 64, 0x12))
            .expect("authority content");
    let digest = content
        .content()
        .public_plaintext_sha256()
        .expect("runtime authority public digest");
    let generation = RuntimeAuthorityGeneration::new(1).expect("authority generation");
    let acknowledgement_operation_id = OperationId::new();
    let authority = RuntimeAuthorityDeliveryRecord::new(
        RuntimeAuthorityDeliveryBinding::new(
            lease.attempt_id(),
            slot,
            lease.guard(),
            offer.command().operation_id(),
            offer.command().sequence(),
            offer
                .job_ir()
                .content()
                .public_plaintext_sha256()
                .expect("job IR public digest"),
            generation,
        ),
        OperationId::new(),
        acknowledgement_operation_id,
        digest,
        content,
        None,
    )
    .expect("authority delivery");
    journal
        .record_runtime_authority_delivery(session_id, slot, lease.guard(), authority)
        .expect("record authority delivery");
    journal
        .acknowledge_runtime_authority_delivery(
            session_id,
            slot,
            lease.guard(),
            generation,
            digest,
            acknowledgement_operation_id,
        )
        .expect("acknowledge authority delivery");
}

fn record_test_sandbox(
    journal: &FileJournal,
    session_id: RunnerSessionId,
    slot: RunnerSlotOrdinal,
    lease: &Lease,
) -> SandboxHandle {
    let provider_id = ProviderId::new("test-provider").expect("provider id");
    let handle = SandboxHandle::new(provider_id, "sandbox-handle").expect("handle");
    let create_id = OperationId::new();
    journal
        .record_provider_intent(
            session_id,
            slot,
            lease.guard(),
            ProviderOperation::intent(create_id, ProviderOperationKind::CreateSandbox),
        )
        .expect("create intent");
    journal
        .record_sandbox_created(
            session_id,
            slot,
            lease.guard(),
            create_id,
            SandboxIdentity::new(
                ProviderName::new(handle.provider().as_str()).expect("journal provider"),
                JournalSandboxHandle::new(handle.opaque()).expect("journal handle"),
            ),
        )
        .expect("sandbox identity");
    handle
}

impl Fixture {
    fn new(label: &str) -> Self {
        Self::new_with_spool_limits(label, None)
    }

    fn new_with_spool_limits(label: &str, spool_limits: Option<SpoolLimits>) -> Self {
        let scratch = Scratch::new(label);
        let runner_id = RunnerId::new();
        let session_id = RunnerSessionId::new();
        let slot = RunnerSlotOrdinal::new(1).expect("slot");
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(7).expect("fence"),
            UnixMillis::new(1_000),
            UnixMillis::new(10_000),
        )
        .expect("lease");
        let journal_fault = Arc::new(ArmableJournalFault::default());
        let state_root = StateRoot::explicit(scratch.child("state")).expect("state root");
        let journal = Arc::new(
            FileJournal::open_with_options(
                state_root,
                runner_id,
                FileJournalOptions::new().with_fault_injector(journal_fault.clone()),
            )
            .expect("journal"),
        );
        journal
            .begin_session(SessionBinding::new(
                session_id,
                PROTOCOL_MAX_VERSION,
                JobIrVersion::current(),
            ))
            .expect("session");
        let offer = LeaseOfferRecord::new(
            slot,
            lease.clone(),
            JobIrContentRef::new(
                JobIrVersion::current(),
                content_ref(ContentKind::JobIr, 64, 0x11),
            )
            .expect("job content"),
            DurableCommand::new(
                CommandSequence::new(1).expect("command"),
                OperationId::new(),
                Sha256Digest::from_bytes([0x13; 32]),
            ),
        )
        .expect("offer");
        journal
            .record_lease_offer(session_id, offer.clone())
            .expect("record offer");
        journal
            .accept_lease(session_id, slot, lease.guard())
            .expect("accept offer");
        record_test_runtime_authority(journal.as_ref(), session_id, slot, &lease, &offer);
        let handle = record_test_sandbox(journal.as_ref(), session_id, slot, &lease);
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("test.provider/linux").expect("profile id"),
            Sha256Digest::from_bytes([0x44; 32]),
        );
        let inspection = SandboxInspection::new(
            handle,
            SandboxGeneration::new(lease.fencing_token().get()).expect("generation"),
            SandboxCustody::Job {
                runner_id,
                slot_ordinal: NonZeroU16::new(slot.get()).expect("slot custody"),
            },
            profile,
            SandboxState::Running,
        );
        let provider = Arc::new(FakeProvider::new(inspection.clone()));
        let spool_fault = Arc::new(ArmableContentFault::default());
        let spool_root = SpoolRoot::explicit(scratch.child("spool")).expect("spool root");
        let mut spool_options = FileSpoolOptions::new().with_fault_injector(spool_fault.clone());
        if let Some(limits) = spool_limits {
            spool_options = spool_options.with_limits(limits);
        }
        let spool = Arc::new(
            FileSpool::open_with_options(spool_root, Arc::new(TestProtector::new()), spool_options)
                .expect("spool"),
        );
        Self {
            scratch,
            journal,
            spool,
            coordinator: Arc::new(ContentOperationCoordinator::default()),
            serial: Arc::new(Mutex::new(())),
            provider,
            inspection,
            session_id,
            slot,
            guard: lease.guard(),
            calls: Arc::new(AtomicUsize::new(0)),
            terminations: Arc::new(AtomicUsize::new(0)),
            journal_fault,
            spool_fault,
        }
    }

    fn endpoint(&self) -> DurableExecutionEndpoint {
        DurableExecutionEndpoint::bind(
            self.journal.clone(),
            self.spool.clone(),
            self.coordinator.clone(),
            self.serial.clone(),
            self.session_id,
            self.slot,
            self.guard,
            self.provider.clone(),
            self.inspection.clone(),
            Box::new(FakeEndpoint {
                handle: self.inspection.handle().clone(),
                calls: self.calls.clone(),
                terminations: self.terminations.clone(),
            }),
        )
        .expect("bind durable endpoint")
    }

    fn request(operation_id: OperationId, source: &str) -> CopyFromRequest {
        CopyFromRequest::new(
            operation_id,
            TargetPath::posix(source).expect("source path"),
            1024,
        )
        .expect("copy request")
    }
}

fn content_ref(kind: ContentKind, size: u64, marker: u8) -> DurableContentRef {
    DurableContentRef::after_public_commit(
        kind,
        size,
        Sha256Digest::from_bytes([marker; 32]),
        ProtectionId::new("endpoint-replay-test-v1").expect("protection id"),
    )
    .expect("content ref")
}

#[test]
fn completed_result_replays_without_backend_and_result_wins_later_cancellation() {
    let fixture = Fixture::new("completed");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/result");
    let first = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect("first result");
    assert_eq!(first, b"protected replay result");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);

    let replay = fixture
        .endpoint()
        .copy_from(
            &request,
            &SequencedCancellation::after(0, CancellationDisposition::Terminate),
        )
        .expect("durable result wins later cancellation");
    assert_eq!(replay, first);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);

    let conflict = fixture.endpoint().copy_from(
        &Fixture::request(operation_id, "/workspace/different"),
        &automata_ci_execution::NeverCancelled,
    );
    assert_eq!(
        conflict.expect_err("request fingerprint conflict").kind(),
        ExecutionErrorKind::InvalidState
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn secret_bearing_requests_never_serialize_into_journal_spool_identity_or_debug() {
    let fixture = Fixture::new("request-secret-redaction");
    let secret = "pin-0427";
    let command = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            TargetPath::posix("/usr/bin/printf").expect("program"),
            vec![secret.to_owned()],
        )
        .expect("argv"),
        TargetPath::posix("/workspace").expect("working directory"),
        ExecutionEnvironment::new(vec![EnvironmentVariable::secret(
            EnvironmentName::new("LOW_ENTROPY_PIN").expect("name"),
            EnvironmentValue::new(secret).expect("value"),
        )])
        .expect("environment"),
        Duration::from_secs(30),
        1024,
    )
    .expect("command");
    let error = fixture
        .endpoint()
        .exec(&command, &automata_ci_execution::NeverCancelled)
        .expect_err("fake endpoint reports unsupported exec");
    assert!(!format!("{command:?}{error:?}").contains(secret));

    let snapshot = fixture.journal.snapshot().expect("snapshot");
    let request_ref = snapshot
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0]
        .request()
        .content();
    let raw_secret_digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    assert_ne!(
        request_ref
            .public_plaintext_sha256()
            .expect("request commitment public digest")
            .as_bytes(),
        raw_secret_digest.as_slice()
    );
    let journal_bytes = fs::read(fixture.scratch.child("state").join("runner-journal.json"))
        .expect("journal bytes");
    assert!(
        !journal_bytes
            .windows(secret.len())
            .any(|bytes| bytes == secret.as_bytes())
    );
    for entry in fs::read_dir(fixture.scratch.child("spool")).expect("spool directory") {
        let entry = entry.expect("spool entry");
        if entry.file_type().expect("entry type").is_file() {
            let bytes = fs::read(entry.path()).expect("spool file");
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|part| part == secret.as_bytes())
            );
        }
    }
}

#[test]
fn endpoint_result_journal_identity_exposes_neither_plaintext_digest_nor_exact_size() {
    let fixture = Fixture::new("result-secret-redaction");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/low-entropy-secret");
    let plaintext = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect("endpoint result");
    let digest = Sha256Digest::from_bytes(Sha256::digest(&plaintext).into()).to_string();
    let snapshot = fixture.journal.snapshot().expect("snapshot");
    let result = snapshot
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0]
        .result()
        .expect("durable result")
        .content();
    assert_eq!(result.public_plaintext_bytes(), None);
    assert_eq!(result.public_plaintext_sha256(), None);
    assert_eq!(result.endpoint_result_allocation_bytes(), Some(65_536));

    let debug = format!("{result:?}");
    let journal = fs::read_to_string(fixture.scratch.child("state").join("runner-journal.json"))
        .expect("journal bytes");
    for exposed in [&debug, result.cache_key().as_str()] {
        assert!(!exposed.contains(&digest));
        assert!(!exposed.contains("plaintext_sha256"));
        assert!(!exposed.contains("plaintext_bytes"));
    }
    assert!(!journal.contains(&digest));
    let result_metadata = journal
        .split_once("\"phase\":\"completed\",\"result\":")
        .map(|(_, result)| result)
        .expect("completed result metadata");
    assert!(!result_metadata.contains("plaintext_sha256"));
    assert!(!result_metadata.contains("plaintext_bytes"));
    assert_ne!(
        result.accounted_bytes(),
        u64::try_from(plaintext.len()).expect("bounded plaintext")
    );
    for entry in fs::read_dir(fixture.scratch.child("spool")).expect("spool directory") {
        let entry = entry.expect("spool entry");
        if entry.file_type().expect("entry type").is_file() {
            let protected = fs::read(entry.path()).expect("spool file");
            assert!(
                !protected
                    .windows(plaintext.len())
                    .any(|bytes| bytes == plaintext)
            );
        }
    }
}

#[test]
fn multiple_bindings_share_one_host_operation_linearization_gate() {
    let fixture = Fixture::new("multiple-bindings");
    let request = Fixture::request(OperationId::new(), "/workspace/concurrent");
    let left = fixture.endpoint();
    let right = fixture.endpoint();
    let barrier = Arc::new(Barrier::new(2));
    let (left_result, right_result) = std::thread::scope(|scope| {
        let left_request = request.clone();
        let left_barrier = barrier.clone();
        let left = scope.spawn(move || {
            left_barrier.wait();
            left.copy_from(&left_request, &automata_ci_execution::NeverCancelled)
        });
        let right_barrier = barrier.clone();
        let right = scope.spawn(move || {
            right_barrier.wait();
            right.copy_from(&request, &automata_ci_execution::NeverCancelled)
        });
        (
            left.join().expect("left endpoint thread"),
            right.join().expect("right endpoint thread"),
        )
    });
    assert_eq!(
        left_result.expect("left result"),
        b"protected replay result"
    );
    assert_eq!(
        right_result.expect("right result"),
        b"protected replay result"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.provider.inspections.load(Ordering::SeqCst), 1);
}

#[test]
fn unresolved_invocation_committed_always_fails_closed() {
    let fixture = Fixture::new("ambiguous");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/ambiguous");
    fixture
        .spool_fault
        .arm_after(ContentCommitStage::FileSynced, 1);
    let first = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled);
    assert_eq!(
        first
            .expect_err("result publication leaves ambiguity")
            .kind(),
        ExecutionErrorKind::LocalStorage
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let operation = fixture
        .journal
        .snapshot()
        .expect("snapshot")
        .slot(fixture.slot)
        .unwrap()
        .endpoint_operations()[0]
        .clone();
    assert_eq!(
        operation.state(),
        &EndpointOperationState::InvocationCommitted
    );

    let replay = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled);
    assert_eq!(
        replay
            .expect_err("unsafe ambiguous replay is fenced")
            .kind(),
        ExecutionErrorKind::InvalidState
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.provider.inspections.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_cannot_resolve_committed_ambiguity_before_sandbox_absence() {
    let fixture = Fixture::new("ambiguous-cancellation");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/ambiguous-cancellation");
    fixture
        .spool_fault
        .arm_after(ContentCommitStage::FileSynced, 1);
    fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect_err("seed invocation-committed ambiguity");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);

    let cancelled = fixture.endpoint().copy_from(
        &request,
        &SequencedCancellation::after(0, CancellationDisposition::Terminate),
    );
    assert_eq!(
        cancelled
            .expect_err("recovered ambiguity cannot be completed by a new caller")
            .kind(),
        ExecutionErrorKind::InvalidState
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let snapshot = fixture.journal.snapshot().expect("snapshot");
    let operation = &snapshot
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0];
    assert_eq!(
        operation.state(),
        &EndpointOperationState::InvocationCommitted
    );
}

#[test]
fn termination_is_durable_before_backend_observes_it() {
    let fixture = Fixture::new("termination");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/cancel");
    let cancelled = fixture.endpoint().copy_from(
        &request,
        &SequencedCancellation::after(2, CancellationDisposition::Terminate),
    );
    assert_eq!(
        cancelled.expect_err("termination wins").kind(),
        ExecutionErrorKind::Cancelled
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let snapshot = fixture.journal.snapshot().expect("snapshot cancellation");
    let operation = &snapshot
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0];
    assert_eq!(
        operation.state(),
        &EndpointOperationState::CancellationRequested
    );
    assert!(operation.result().is_none());
    assert_eq!(fixture.terminations.load(Ordering::SeqCst), 1);
}

#[test]
fn pre_invocation_termination_resolves_acceptance_without_backend_exposure() {
    let fixture = Fixture::new("pre-invocation-termination");
    let request = Fixture::request(OperationId::new(), "/workspace/pre-invocation-cancel");
    let cancelled = fixture.endpoint().copy_from(
        &request,
        &SequencedCancellation::after(0, CancellationDisposition::Terminate),
    );
    assert_eq!(
        cancelled
            .expect_err("termination wins before invocation")
            .kind(),
        ExecutionErrorKind::Cancelled
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.provider.inspections.load(Ordering::SeqCst), 0);
    let snapshot = fixture.journal.snapshot().expect("snapshot cancellation");
    assert_eq!(
        snapshot
            .slot(fixture.slot)
            .expect("slot")
            .endpoint_operations()[0]
            .state(),
        &EndpointOperationState::Cancelled
    );
}

#[test]
fn request_spool_or_acceptance_fault_never_reaches_the_backend() {
    let spool_fault = Fixture::new("request-spool-fault");
    spool_fault.spool_fault.arm(ContentCommitStage::FileSynced);
    let request = Fixture::request(OperationId::new(), "/workspace/request-spool");
    let error = spool_fault
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect_err("request content must be durable first");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(spool_fault.calls.load(Ordering::SeqCst), 0);
    assert!(
        spool_fault
            .journal
            .snapshot()
            .expect("snapshot")
            .slot(spool_fault.slot)
            .expect("slot")
            .endpoint_operations()
            .is_empty()
    );

    let journal_fault = Fixture::new("request-journal-fault");
    journal_fault.journal_fault.arm(CommitStage::FileSynced);
    let request = Fixture::request(OperationId::new(), "/workspace/request-journal");
    let error = journal_fault
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect_err("acceptance must commit before invocation");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(journal_fault.calls.load(Ordering::SeqCst), 0);
    assert!(
        journal_fault
            .journal
            .snapshot()
            .expect("snapshot")
            .slot(journal_fault.slot)
            .expect("slot")
            .endpoint_operations()
            .is_empty()
    );
}

#[test]
fn invocation_commit_fault_never_reaches_the_backend() {
    let fixture = Fixture::new("invocation-commit-fault");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/invocation");
    fixture.journal_fault.arm_after(CommitStage::FileSynced, 1);
    let error = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect_err("invocation commitment must be durable");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let snapshot = fixture.journal.snapshot().expect("snapshot");
    let operation = &snapshot
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0];
    assert_eq!(operation.state(), &EndpointOperationState::Accepted);
}

#[test]
fn shared_result_capacity_is_reserved_before_provider_inspection_or_backend_invocation() {
    let limits = SpoolLimits::new(2_048, 67_584, 1, 65_536).expect("bounded one-object spool");
    let fixture = Fixture::new_with_spool_limits("result-capacity-before-provider", Some(limits));
    let request = Fixture::request(OperationId::new(), "/workspace/capacity");
    let error = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect_err("request content consumes the only shared object slot");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(fixture.provider.inspections.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let snapshot = fixture.journal.snapshot().expect("snapshot");
    assert_eq!(
        snapshot
            .slot(fixture.slot)
            .expect("slot")
            .endpoint_operations()[0]
            .state(),
        &EndpointOperationState::Accepted
    );
}

#[test]
fn failed_binding_releases_shared_result_capacity_for_the_exact_accepted_retry() {
    let limits = SpoolLimits::new(2_048, 67_584, 2, 65_536).expect("bounded two-object spool");
    let fixture = Fixture::new_with_spool_limits("result-capacity-release", Some(limits));
    let request = Fixture::request(OperationId::new(), "/workspace/capacity-release");
    let exited = SandboxInspection::new(
        fixture.inspection.handle().clone(),
        fixture.inspection.generation(),
        fixture.inspection.custody(),
        fixture.inspection.profile().clone(),
        SandboxState::Stopped,
    );
    *fixture.provider.inspection.lock().expect("inspection lock") = exited;
    assert_eq!(
        fixture
            .endpoint()
            .copy_from(&request, &automata_ci_execution::NeverCancelled)
            .expect_err("exited binding")
            .kind(),
        ExecutionErrorKind::InvalidState
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);

    *fixture.provider.inspection.lock().expect("inspection lock") = fixture.inspection.clone();
    assert_eq!(
        fixture
            .endpoint()
            .copy_from(&request, &automata_ci_execution::NeverCancelled)
            .expect("exact accepted retry after reservation release"),
        b"protected replay result"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.spool.usage().expect("spool usage").0, 2);
}

#[test]
fn result_spool_fault_leaves_committed_ambiguity_fenced() {
    let fixture = Fixture::new("result-spool-fault");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/result-spool");
    fixture
        .spool_fault
        .arm_after(ContentCommitStage::FileSynced, 1);
    let error = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect_err("result publication fails");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.terminations.load(Ordering::SeqCst), 0);
    let snapshot = fixture.journal.snapshot().expect("snapshot");
    let operation = &snapshot
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0];
    assert_eq!(
        operation.state(),
        &EndpointOperationState::InvocationCommitted
    );

    let replay = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect_err("ambiguous non-replay provider stays fenced");
    assert_eq!(replay.kind(), ExecutionErrorKind::InvalidState);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn result_journal_fault_preserves_payload_first_ambiguous_state() {
    let fixture = Fixture::new("result-journal-fault");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/result-journal");
    fixture.journal_fault.arm_after(CommitStage::FileSynced, 2);
    let error = fixture
        .endpoint()
        .copy_from(&request, &automata_ci_execution::NeverCancelled)
        .expect_err("result journal adoption fails");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.terminations.load(Ordering::SeqCst), 0);
    let snapshot = fixture.journal.snapshot().expect("snapshot");
    let operation = &snapshot
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0];
    assert_eq!(
        operation.state(),
        &EndpointOperationState::InvocationCommitted
    );
    assert!(operation.result().is_none());
    assert_eq!(
        fixture.spool.usage().expect("spool usage").0,
        2,
        "the protected result remains an unreferenced payload-first object"
    );
}

#[test]
fn cancellation_journal_fault_terminates_backend_but_leaves_durable_ambiguity() {
    let fixture = Fixture::new("cancellation-journal-fault");
    let operation_id = OperationId::new();
    let request = Fixture::request(operation_id, "/workspace/cancel-journal");
    fixture.journal_fault.arm_after(CommitStage::FileSynced, 2);
    let error = fixture
        .endpoint()
        .copy_from(
            &request,
            &SequencedCancellation::after(2, CancellationDisposition::Terminate),
        )
        .expect_err("cancellation storage failure wins wrapper result");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.terminations.load(Ordering::SeqCst), 1);
    let snapshot = fixture.journal.snapshot().expect("snapshot");
    let operation = &snapshot
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0];
    assert_eq!(
        operation.state(),
        &EndpointOperationState::InvocationCommitted
    );
    assert!(operation.result().is_none());
}

#[test]
fn pre_invocation_cancellation_storage_failure_never_reaches_provider_or_backend() {
    let fixture = Fixture::new("pre-invocation-cancellation-journal-fault");
    let request = Fixture::request(OperationId::new(), "/workspace/pre-cancel-storage");
    fixture.journal_fault.arm_after(CommitStage::FileSynced, 1);
    let error = fixture
        .endpoint()
        .copy_from(
            &request,
            &SequencedCancellation::after(0, CancellationDisposition::Terminate),
        )
        .expect_err("cancellation cannot reach provider before its durable transition");
    assert_eq!(error.kind(), ExecutionErrorKind::LocalStorage);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.provider.inspections.load(Ordering::SeqCst), 0);
    let snapshot = fixture.journal.snapshot().expect("snapshot");
    assert_eq!(
        snapshot
            .slot(fixture.slot)
            .expect("slot")
            .endpoint_operations()[0]
            .state(),
        &EndpointOperationState::Accepted
    );
}
