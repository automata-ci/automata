use std::time::Duration;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    MediaType, MemoryBlobStore, PutBlobOutcome, VerifiedBlob,
};
use automata_ci_core::{
    ContextValue, JobAuthorityProfile, JobConclusion, JobPermissionRequest, JobRuntimeContext,
    OutputSensitivity, RunId, RunIdAlias, SecretBinding, Sha256Digest, UnixMillis,
    WorkflowEventProvenance, WorkflowId, WorkflowJobKey, WorkflowOutputKey, WorkflowPlan,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    AdmissionObject, BindLogicalActivationPreparation, ClaimNextLogicalInstanceMaterialization,
    ClaimNextLogicalJobOrchestration, ClaimedLogicalActivationPreparation,
    ClaimedLogicalInstanceMaterialization, ClaimedLogicalJobActivation,
    CommitLogicalInstanceMaterialization, ConsumeSelectedLogicalInstanceMaterialization,
    ConsumeSelectedLogicalJobOrchestration, ConsumedLogicalJobOrchestrationAuthority,
    ConsumedSelectedLogicalInstanceMaterialization, ConsumedSelectedLogicalJobOrchestration,
    JobEventTrust, JobSourceKind, LogicalActivationBaseContextKind, LogicalActivationClaimFence,
    LogicalActivationExecutionContext, LogicalActivationGeneration, LogicalActivationObject,
    LogicalActivationPreparationClaimFence, LogicalActivationPreparationDescriptor,
    LogicalActivationPreparationGeneration, LogicalActivationPreparationReceipt,
    LogicalActivationPreparationStore, LogicalActivationPreparationStoreError,
    LogicalActivationPreparationTarget, LogicalActivationPrerequisiteEvidence,
    LogicalActivationPrerequisiteOutput, LogicalActivationPublicationReceipt,
    LogicalActivationRepository, LogicalActivationStoreError, LogicalActivationWorkerId,
    LogicalInstanceMaterializationDescriptor, LogicalInstanceMaterializationSelectionOutcome,
    LogicalInstanceMaterializationTarget, LogicalJobOrchestrationAuthorityKind,
    LogicalJobOrchestrationSelectionOutcome, LogicalMaterializationClaimFence,
    LogicalMaterializationGeneration, LogicalMaterializationReceipt,
    LogicalMaterializationRepository, LogicalMaterializationStoreError,
    LogicalMaterializationWorkerId, LogicalWorkQuarantineKind, LogicalWorkQuarantineOutcome,
    LogicalWorkSelectionGeneration, LogicalWorkSelectionId, LogicalWorkSelectionRepository,
    LogicalWorkSelectionStoreError, LogicalWorkflowInstanceId, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, MAX_LOGICAL_WORK_SELECTION_MILLIS, ObjectKey,
    PinnedWorkflowRuntimePolicy, PublishLogicalJobActivation,
    QuarantineLogicalInstanceMaterialization, QuarantineLogicalJobOrchestration,
    RenewLogicalActivationPreparation, RenewLogicalInstanceMaterialization,
    RenewLogicalJobActivation, RenewedLogicalActivationPreparation,
    RenewedLogicalInstanceMaterialization, RenewedLogicalJobActivation, RepositoryId,
    ReusableSecretPermission, SelectedLogicalInstanceMaterialization,
    SelectedLogicalJobOrchestration, StoreError, TenantScope, WorkflowRuntimePolicy,
    WorkflowRuntimePolicyPin, WorkflowRuntimePolicyRevision,
};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use automata_ci_workflow_service::{
    AdmissionClock, AutonomousActivationLease, AutonomousMaterializationLease,
    AutonomousPreparationLease, AutonomousWorkflowDeadline, AutonomousWorkflowError,
    AutonomousWorkflowExecutionFuture, AutonomousWorkflowExecutionOutcome,
    AutonomousWorkflowOutcome, AutonomousWorkflowPhase, AutonomousWorkflowPhaseExecutor,
    AutonomousWorkflowQueue, AutonomousWorkflowService, GITHUB_RUNNER_POLICY_MEDIA_TYPE,
    GithubAutonomousWorkflowPhaseExecutor, JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    WORKFLOW_EVENT_MEDIA_TYPE, WORKFLOW_PLAN_MEDIA_TYPE,
};
use bytes::Bytes;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const REPOSITORY: &str = "synthetic/autonomous";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_PATH: &str = ".ci/workflows/autonomous.yml";
const GIT_REF: &str = "refs/heads/main";
const FINAL_DRAIN_MILLIS: u64 = 30_000;
const FINAL_DRAIN_RETRY_MILLIS: u64 = 250;
const FINAL_DRAIN_SUBMISSION_CAP: usize =
    (FINAL_DRAIN_MILLIS / FINAL_DRAIN_RETRY_MILLIS) as usize + 1;

const RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":[],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","id":"github/ubuntu-24-04"},
    "selector":"ubuntu-latest"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

const WORKFLOW_SOURCE: &str = r"name: Autonomous CI
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo autonomous
";

const WORKFLOW_WITH_NEEDS_SOURCE: &str = r"name: Autonomous CI
on: workflow_dispatch
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - run: echo setup
  build:
    needs: setup
    runs-on: ubuntu-latest
    steps:
      - run: echo autonomous
";

const OUTPUT_DRIVEN_MATRIX_SOURCE: &str = r"name: Autonomous CI
on: workflow_dispatch
jobs:
  plan:
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.emit.outputs.matrix }}
    steps:
      - id: emit
        run: echo matrix
  build:
    needs: plan
    strategy:
      matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}
    runs-on: ubuntu-latest
    steps:
      - run: echo matrix job
";

const OUTPUT_DRIVEN_MATRIX_VALUE: &str = r#"{
  "profile": [
    {
      "name": "stable",
      "options": ["fast", true],
      "metadata": {"tier": "primary"}
    },
    {
      "name": "preview",
      "options": ["safe", false],
      "metadata": {"tier": "secondary"}
    }
  ],
  "shard": [1, 2],
  "exclude": [
    {"profile": {"metadata": {"tier": "primary"}}, "shard": 2}
  ],
  "include": [
    {
      "profile": {
        "name": "stable",
        "options": ["fast", true],
        "metadata": {"tier": "primary"}
      },
      "shard": 1,
      "settings": {"retry": 3, "enabled": true}
    },
    {
      "profile": {
        "name": "edge",
        "options": [],
        "metadata": {"tier": "experimental"}
      },
      "shard": 3,
      "settings": {"retry": 0, "enabled": false}
    }
  ]
}"#;

const MATRIX_CREDENTIAL_FREE_SOURCE: &str = r"name: Autonomous CI
on: workflow_dispatch
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target: [alpha, beta]
    steps:
      - run: echo ${{ matrix.target }}
";

const ZERO_INSTANCE_SOURCE: &str = r"name: Autonomous CI
on: workflow_dispatch
jobs:
  build:
    if: ${{ false }}
    runs-on: ubuntu-latest
    steps:
      - run: echo skipped
";

#[derive(Debug)]
struct TestClock {
    now: AtomicI64,
}

impl TestClock {
    const fn new(now: i64) -> Self {
        Self {
            now: AtomicI64::new(now),
        }
    }
}

impl AdmissionClock for TestClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.now.fetch_add(1, Ordering::SeqCst))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarnessOperation {
    ClaimOrchestration,
    ClaimMaterialization,
    ConsumeOrchestration,
    ConsumeMaterialization,
    QuarantineOrchestration,
    QuarantineMaterialization,
    RenewPreparation,
    BindPreparation,
    RenewActivation,
    PublishActivation,
    RenewMaterialization,
    CommitMaterialization,
    BlobPut,
    BlobGet,
}

#[derive(Clone, Debug, Default)]
struct HarnessTrace {
    operations: Arc<Mutex<Vec<HarnessOperation>>>,
    repository_active: Arc<AtomicBool>,
}

impl HarnessTrace {
    fn begin_repository(&self, operation: HarnessOperation) -> ActiveRepositoryCall {
        assert!(
            !self.repository_active.swap(true, Ordering::SeqCst),
            "repository calls must not overlap"
        );
        self.operations
            .lock()
            .expect("operation trace")
            .push(operation);
        ActiveRepositoryCall {
            repository_active: self.repository_active.clone(),
        }
    }

    fn record_blob(&self, operation: HarnessOperation) {
        assert!(
            !self.repository_active.load(Ordering::SeqCst),
            "blob I/O must not overlap a repository call"
        );
        self.operations
            .lock()
            .expect("operation trace")
            .push(operation);
    }

    fn take(&self) -> Vec<HarnessOperation> {
        std::mem::take(&mut *self.operations.lock().expect("operation trace"))
    }

    fn reset(&self) {
        self.operations.lock().expect("operation trace").clear();
    }
}

#[derive(Debug)]
struct ActiveRepositoryCall {
    repository_active: Arc<AtomicBool>,
}

impl Drop for ActiveRepositoryCall {
    fn drop(&mut self) {
        assert!(self.repository_active.swap(false, Ordering::SeqCst));
    }
}

#[derive(Debug, Default)]
struct BlobFault {
    operations: usize,
    created: usize,
    already_present: usize,
    fail_next: Option<BlobStoreErrorKind>,
    cancel_after: Option<(usize, CancellationToken)>,
}

#[derive(Clone, Debug, Default)]
struct FaultBlobStore {
    inner: MemoryBlobStore,
    fault: Arc<Mutex<BlobFault>>,
    trace: HarnessTrace,
}

impl FaultBlobStore {
    fn new(trace: HarnessTrace) -> Self {
        Self {
            inner: MemoryBlobStore::default(),
            fault: Arc::new(Mutex::new(BlobFault::default())),
            trace,
        }
    }

    fn fail_next(&self, kind: BlobStoreErrorKind) {
        let mut fault = self.fault.lock().expect("blob fault");
        fault.operations = 0;
        fault.fail_next = Some(kind);
        fault.cancel_after = None;
    }

    fn cancel_after(&self, operation: usize, shutdown: CancellationToken) {
        let mut fault = self.fault.lock().expect("blob fault");
        fault.operations = 0;
        fault.fail_next = None;
        fault.cancel_after = Some((operation, shutdown));
    }

    fn reset_observation(&self) {
        let mut fault = self.fault.lock().expect("blob fault");
        fault.operations = 0;
        fault.created = 0;
        fault.already_present = 0;
        fault.fail_next = None;
        fault.cancel_after = None;
    }

    fn operations(&self) -> usize {
        self.fault.lock().expect("blob fault").operations
    }

    fn put_outcomes(&self) -> (usize, usize) {
        let fault = self.fault.lock().expect("blob fault");
        (fault.created, fault.already_present)
    }

    fn begin_operation(
        &self,
        operation: HarnessOperation,
    ) -> Result<Option<CancellationToken>, BlobStoreError> {
        self.trace.record_blob(operation);
        let mut fault = self.fault.lock().expect("blob fault");
        fault.operations += 1;
        if let Some(kind) = fault.fail_next.take() {
            return Err(BlobStoreError::new(kind));
        }
        Ok(fault
            .cancel_after
            .as_ref()
            .filter(|(operation, _)| *operation == fault.operations)
            .map(|(_, shutdown)| shutdown.clone()))
    }
}

#[async_trait]
impl ImmutableBlobStore for FaultBlobStore {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        let cancellation = self.begin_operation(HarnessOperation::BlobPut)?;
        let outcome = self.inner.put_if_absent(payload).await;
        if let Ok(outcome) = &outcome {
            let mut fault = self.fault.lock().expect("blob fault");
            match outcome {
                PutBlobOutcome::Created => fault.created += 1,
                PutBlobOutcome::AlreadyPresent => fault.already_present += 1,
            }
        }
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
        }
        outcome
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        let cancellation = self.begin_operation(HarnessOperation::BlobGet)?;
        let outcome = self.inner.get_verified(descriptor, maximum_bytes).await;
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
        }
        outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WrongReceipt {
    None,
    Preparation,
    Activation,
    Materialization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalMutationFault {
    OperationAfterCommit,
    OperationBeforeCommit,
    ParkAfterCommit,
    ClaimRejected,
    InvalidTarget,
}

#[derive(Clone, Debug)]
enum ReadyPhase {
    Preparation(Box<LogicalActivationPreparationDescriptor>),
    Activation(Box<LogicalActivationPreparationReceipt>),
    Materialization(Box<LogicalInstanceMaterializationDescriptor>),
    Done,
}

#[derive(Debug)]
struct RepositoryState {
    ready: ReadyPhase,
    orchestration: Option<ConsumedSelectedLogicalJobOrchestration>,
    materialization: Option<ConsumedSelectedLogicalInstanceMaterialization>,
    wrong_receipt: WrongReceipt,
    next_binding_fault: Option<FinalMutationFault>,
    next_publication_fault: Option<FinalMutationFault>,
    next_commit_fault: Option<FinalMutationFault>,
    park_every_binding_attempt: bool,
    durable_binding: Option<BindLogicalActivationPreparation>,
    durable_publication: Option<PublishLogicalJobActivation>,
    durable_commit: Option<CommitLogicalInstanceMaterialization>,
    swap_initial_materialization_consume: bool,
    swap_activation_reconcile: bool,
    change_activation_evidence_on_renew: Option<usize>,
    orchestration_selections: usize,
    materialization_selections: usize,
    orchestration_consumes: usize,
    materialization_consumes: usize,
    preparation_renews: usize,
    activation_renews: usize,
    materialization_renews: usize,
    binds: Vec<BindLogicalActivationPreparation>,
    publications: Vec<PublishLogicalJobActivation>,
    successful_publications: usize,
    commits: Vec<CommitLogicalInstanceMaterialization>,
    orchestration_quarantines: Vec<LogicalWorkQuarantineKind>,
    materialization_quarantines: Vec<LogicalWorkQuarantineKind>,
}

#[derive(Debug)]
struct HarnessRepository {
    state: Mutex<RepositoryState>,
    trace: HarnessTrace,
    final_mutation_parked: AtomicBool,
    final_mutation_notify: Notify,
}

impl HarnessRepository {
    fn new(descriptor: LogicalActivationPreparationDescriptor, trace: HarnessTrace) -> Self {
        Self {
            state: Mutex::new(RepositoryState {
                ready: ReadyPhase::Preparation(Box::new(descriptor)),
                orchestration: None,
                materialization: None,
                wrong_receipt: WrongReceipt::None,
                next_binding_fault: None,
                next_publication_fault: None,
                next_commit_fault: None,
                park_every_binding_attempt: false,
                durable_binding: None,
                durable_publication: None,
                durable_commit: None,
                swap_initial_materialization_consume: false,
                swap_activation_reconcile: false,
                change_activation_evidence_on_renew: None,
                orchestration_selections: 0,
                materialization_selections: 0,
                orchestration_consumes: 0,
                materialization_consumes: 0,
                preparation_renews: 0,
                activation_renews: 0,
                materialization_renews: 0,
                binds: Vec::new(),
                publications: Vec::new(),
                successful_publications: 0,
                commits: Vec::new(),
                orchestration_quarantines: Vec::new(),
                materialization_quarantines: Vec::new(),
            }),
            trace,
            final_mutation_parked: AtomicBool::new(false),
            final_mutation_notify: Notify::new(),
        }
    }

    fn set_wrong_receipt(&self, wrong_receipt: WrongReceipt) {
        self.state.lock().expect("repository state").wrong_receipt = wrong_receipt;
    }

    fn fault_next_binding(&self, fault: FinalMutationFault) {
        self.final_mutation_parked.store(false, Ordering::SeqCst);
        self.state
            .lock()
            .expect("repository state")
            .next_binding_fault = Some(fault);
    }

    fn fault_next_publication(&self, fault: FinalMutationFault) {
        self.final_mutation_parked.store(false, Ordering::SeqCst);
        self.state
            .lock()
            .expect("repository state")
            .next_publication_fault = Some(fault);
    }

    fn fault_next_commit(&self, fault: FinalMutationFault) {
        self.final_mutation_parked.store(false, Ordering::SeqCst);
        self.state
            .lock()
            .expect("repository state")
            .next_commit_fault = Some(fault);
    }

    fn park_every_binding_attempt(&self) {
        self.final_mutation_parked.store(false, Ordering::SeqCst);
        self.state
            .lock()
            .expect("repository state")
            .park_every_binding_attempt = true;
    }

    fn release_binding_attempts(&self) {
        self.state
            .lock()
            .expect("repository state")
            .park_every_binding_attempt = false;
    }

    async fn wait_for_final_mutation_to_park(&self) {
        loop {
            let notified = self.final_mutation_notify.notified();
            if self.final_mutation_parked.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    async fn park_final_mutation(&self) -> ! {
        self.final_mutation_parked.store(true, Ordering::SeqCst);
        self.final_mutation_notify.notify_waiters();
        std::future::pending().await
    }

    fn swap_initial_materialization_consume(&self) {
        self.state
            .lock()
            .expect("repository state")
            .swap_initial_materialization_consume = true;
    }

    fn swap_activation_reconcile(&self) {
        self.state
            .lock()
            .expect("repository state")
            .swap_activation_reconcile = true;
    }

    fn change_activation_evidence_on_renew(&self, renewal: usize) {
        self.state
            .lock()
            .expect("repository state")
            .change_activation_evidence_on_renew = Some(renewal);
    }

    fn selection_consume_counts(&self) -> (usize, usize, usize, usize) {
        let state = self.state.lock().expect("repository state");
        (
            state.orchestration_selections,
            state.materialization_selections,
            state.orchestration_consumes,
            state.materialization_consumes,
        )
    }

    fn bind_generations(&self) -> Vec<u64> {
        self.state
            .lock()
            .expect("repository state")
            .binds
            .iter()
            .map(|request| request.claim().generation().get())
            .collect()
    }

    fn publication_generations(&self) -> Vec<u64> {
        self.state
            .lock()
            .expect("repository state")
            .publications
            .iter()
            .map(|request| request.claim().generation().get())
            .collect()
    }

    fn commit_generations(&self) -> Vec<u64> {
        self.state
            .lock()
            .expect("repository state")
            .commits
            .iter()
            .map(|request| request.claim().generation().get())
            .collect()
    }

    fn renewal_counts(&self) -> (usize, usize, usize) {
        let state = self.state.lock().expect("repository state");
        (
            state.preparation_renews,
            state.activation_renews,
            state.materialization_renews,
        )
    }

    fn quarantine_kinds(
        &self,
    ) -> (
        Vec<LogicalWorkQuarantineKind>,
        Vec<LogicalWorkQuarantineKind>,
    ) {
        let state = self.state.lock().expect("repository state");
        (
            state.orchestration_quarantines.clone(),
            state.materialization_quarantines.clone(),
        )
    }

    fn mutation_counts(&self) -> (usize, usize, usize) {
        let state = self.state.lock().expect("repository state");
        (
            state.binds.len(),
            state.publications.len(),
            state.commits.len(),
        )
    }

    fn last_binding(&self) -> BindLogicalActivationPreparation {
        self.state
            .lock()
            .expect("repository state")
            .binds
            .last()
            .expect("preparation binding")
            .clone()
    }

    fn binding_attempts(&self) -> Vec<BindLogicalActivationPreparation> {
        self.state.lock().expect("repository state").binds.clone()
    }

    fn publication_attempts(&self) -> Vec<PublishLogicalJobActivation> {
        self.state
            .lock()
            .expect("repository state")
            .publications
            .clone()
    }

    fn commit_attempts(&self) -> Vec<CommitLogicalInstanceMaterialization> {
        self.state.lock().expect("repository state").commits.clone()
    }

    fn successful_publications(&self) -> usize {
        self.state
            .lock()
            .expect("repository state")
            .successful_publications
    }

    fn ready_materialization_descriptor(&self) -> LogicalInstanceMaterializationDescriptor {
        let state = self.state.lock().expect("repository state");
        let ReadyPhase::Materialization(descriptor) = &state.ready else {
            panic!("materialization-ready descriptor")
        };
        descriptor.as_ref().clone()
    }

    fn replace_ready_runtime_context(&self, runtime_context: LogicalActivationObject) {
        let mut state = self.state.lock().expect("repository state");
        let ReadyPhase::Materialization(current) = &state.ready else {
            panic!("materialization-ready descriptor")
        };
        let replacement = LogicalInstanceMaterializationDescriptor::new(
            current.target().clone(),
            current.logical_key().clone(),
            current.matrix_index(),
            current.matrix_total(),
            current.matrix_digest(),
            current.workspace().to_owned(),
            current.job_ir().clone(),
            runtime_context,
            current.event().clone(),
            current.execution().clone(),
            current.authority_profile(),
            current.runtime_policy().clone(),
        )
        .expect("replacement materialization descriptor");
        state.ready = ReadyPhase::Materialization(Box::new(replacement));
        state.materialization = None;
    }
}

fn selection_interval(observed_at: UnixMillis, duration_ms: i64) -> (UnixMillis, UnixMillis) {
    let expires_at = UnixMillis::new(
        observed_at
            .get()
            .checked_add(duration_ms)
            .expect("selection expiration"),
    );
    (observed_at, expires_at)
}

fn selected_preparation(
    descriptor: LogicalActivationPreparationDescriptor,
    request: &ClaimNextLogicalJobOrchestration,
) -> ConsumedSelectedLogicalJobOrchestration {
    let (claimed_at, expires_at) = selection_interval(request.observed_at(), request.duration_ms());
    let selected = SelectedLogicalJobOrchestration::new(
        request.selection_id(),
        descriptor.target().clone(),
        request.owner(),
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        LogicalJobOrchestrationAuthorityKind::Preparation,
        descriptor.descriptor_digest(),
        claimed_at,
        expires_at,
    )
    .expect("selected preparation");
    let claim = LogicalActivationPreparationClaimFence::new_for_selection(
        descriptor.target().clone(),
        request.owner(),
        LogicalActivationPreparationGeneration::new(1).expect("preparation generation"),
        descriptor.descriptor_digest(),
        claimed_at,
        expires_at,
        request.selection_id(),
    )
    .expect("preparation claim");
    let authority = ClaimedLogicalActivationPreparation::new(descriptor, claim, false)
        .expect("preparation authority");
    ConsumedSelectedLogicalJobOrchestration::new(
        selected,
        ConsumedLogicalJobOrchestrationAuthority::Preparation(authority),
        claimed_at,
    )
    .expect("consumed preparation")
}

fn selected_activation(
    preparation: LogicalActivationPreparationReceipt,
    request: &ClaimNextLogicalJobOrchestration,
) -> ConsumedSelectedLogicalJobOrchestration {
    let descriptor = preparation.descriptor();
    let (claimed_at, expires_at) = selection_interval(request.observed_at(), request.duration_ms());
    let selected = SelectedLogicalJobOrchestration::new(
        request.selection_id(),
        descriptor.target().clone(),
        request.owner(),
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        LogicalJobOrchestrationAuthorityKind::Activation,
        preparation.input_digest(),
        claimed_at,
        expires_at,
    )
    .expect("selected activation");
    let claim = LogicalActivationClaimFence::new_for_selection(
        descriptor.target().tenant().clone(),
        descriptor.target().run_id(),
        descriptor.target().invocation_id(),
        descriptor.target().logical_job_id(),
        request.owner(),
        descriptor.runtime_policy().pin().clone(),
        LogicalActivationGeneration::new(1).expect("activation generation"),
        preparation.input_digest(),
        claimed_at,
        expires_at,
        request.selection_id(),
    )
    .expect("activation claim");
    let authority = ClaimedLogicalJobActivation::new_with_preparation(claim, preparation, false)
        .expect("activation authority");
    ConsumedSelectedLogicalJobOrchestration::new(
        selected,
        ConsumedLogicalJobOrchestrationAuthority::Activation(authority),
        claimed_at,
    )
    .expect("consumed activation")
}

fn selected_materialization(
    descriptor: LogicalInstanceMaterializationDescriptor,
    request: &ClaimNextLogicalInstanceMaterialization,
) -> ConsumedSelectedLogicalInstanceMaterialization {
    let (claimed_at, expires_at) = selection_interval(request.observed_at(), request.duration_ms());
    let selected = SelectedLogicalInstanceMaterialization::new(
        request.selection_id(),
        descriptor.target().clone(),
        request.owner(),
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        descriptor.descriptor_digest(),
        claimed_at,
        expires_at,
    )
    .expect("selected materialization");
    let claim = LogicalMaterializationClaimFence::new_for_selection(
        descriptor.target().clone(),
        request.owner(),
        LogicalMaterializationGeneration::new(1).expect("materialization generation"),
        descriptor.descriptor_digest(),
        descriptor.runtime_policy().clone(),
        descriptor.expected_job_id(),
        descriptor.expected_attempt_id(),
        claimed_at,
        expires_at,
        request.selection_id(),
    )
    .expect("materialization claim");
    let authority = ClaimedLogicalInstanceMaterialization::new(descriptor, claim, false)
        .expect("materialization authority");
    ConsumedSelectedLogicalInstanceMaterialization::new(selected, authority, claimed_at)
        .expect("consumed materialization")
}

fn swapped_activation_consumed(
    consumed: &ConsumedSelectedLogicalJobOrchestration,
) -> ConsumedSelectedLogicalJobOrchestration {
    let ConsumedLogicalJobOrchestrationAuthority::Activation(authority) = consumed.authority()
    else {
        panic!("activation authority")
    };
    let preparation = authority
        .preparation()
        .expect("activation preparation")
        .clone();
    let claim = authority.claim();
    let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(0xfeed))
        .expect("replacement selection ID");
    let replacement_claimed_at = claim.claimed_at();
    let replacement_expires_at = UnixMillis::new(
        replacement_claimed_at
            .get()
            .checked_add(MAX_LOGICAL_WORK_SELECTION_MILLIS)
            .expect("replacement selection interval"),
    );
    let selected = SelectedLogicalJobOrchestration::new(
        selection_id,
        preparation.descriptor().target().clone(),
        claim.owner(),
        LogicalWorkSelectionGeneration::new(claim.generation().get())
            .expect("replacement selection generation"),
        LogicalJobOrchestrationAuthorityKind::Activation,
        claim.input_digest(),
        replacement_claimed_at,
        replacement_expires_at,
    )
    .expect("replacement selection");
    let replacement_claim = LogicalActivationClaimFence::new_for_selection(
        claim.tenant().clone(),
        claim.run_id(),
        claim.invocation_id(),
        claim.logical_job_id(),
        claim.owner(),
        claim.runtime_policy().clone(),
        claim.generation(),
        claim.input_digest(),
        replacement_claimed_at,
        replacement_expires_at,
        selection_id,
    )
    .expect("replacement claim");
    let authority =
        ClaimedLogicalJobActivation::new_with_preparation(replacement_claim, preparation, true)
            .expect("replacement authority");
    ConsumedSelectedLogicalJobOrchestration::new(
        selected,
        ConsumedLogicalJobOrchestrationAuthority::Activation(authority),
        replacement_claimed_at,
    )
    .expect("replacement consumed activation")
}

fn swapped_materialization_consumed(
    consumed: &ConsumedSelectedLogicalInstanceMaterialization,
) -> ConsumedSelectedLogicalInstanceMaterialization {
    let authority = consumed.authority();
    let descriptor = authority.descriptor().clone();
    let claim = authority.claim();
    let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(0xbeef))
        .expect("replacement selection ID");
    let replacement_claimed_at = claim.claimed_at();
    let replacement_expires_at = UnixMillis::new(
        replacement_claimed_at
            .get()
            .checked_add(MAX_LOGICAL_WORK_SELECTION_MILLIS)
            .expect("replacement selection interval"),
    );
    let selected = SelectedLogicalInstanceMaterialization::new(
        selection_id,
        descriptor.target().clone(),
        claim.owner(),
        LogicalWorkSelectionGeneration::new(claim.generation().get())
            .expect("replacement selection generation"),
        descriptor.descriptor_digest(),
        replacement_claimed_at,
        replacement_expires_at,
    )
    .expect("replacement materialization selection");
    let replacement_claim = LogicalMaterializationClaimFence::new_for_selection(
        descriptor.target().clone(),
        claim.owner(),
        claim.generation(),
        descriptor.descriptor_digest(),
        descriptor.runtime_policy().clone(),
        descriptor.expected_job_id(),
        descriptor.expected_attempt_id(),
        replacement_claimed_at,
        replacement_expires_at,
        selection_id,
    )
    .expect("replacement materialization claim");
    let authority = ClaimedLogicalInstanceMaterialization::new(descriptor, replacement_claim, true)
        .expect("replacement materialization authority");
    ConsumedSelectedLogicalInstanceMaterialization::new(selected, authority, replacement_claimed_at)
        .expect("replacement consumed materialization")
}

#[async_trait]
impl LogicalWorkSelectionRepository for HarnessRepository {
    async fn claim_next_logical_job_orchestration(
        &self,
        request: ClaimNextLogicalJobOrchestration,
    ) -> Result<LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::ClaimOrchestration);
        let mut state = self.state.lock().expect("repository state");
        state.orchestration_selections += 1;
        if state.orchestration.is_none() {
            let consumed = match state.ready.clone() {
                ReadyPhase::Preparation(descriptor) => {
                    Some(selected_preparation(*descriptor, &request))
                }
                ReadyPhase::Activation(preparation) => {
                    Some(selected_activation(*preparation, &request))
                }
                ReadyPhase::Materialization(_) | ReadyPhase::Done => None,
            };
            state.orchestration = consumed;
        }
        Ok(state.orchestration.as_ref().map_or(
            LogicalJobOrchestrationSelectionOutcome::Idle,
            |consumed| {
                LogicalJobOrchestrationSelectionOutcome::Selected(consumed.selected().clone())
            },
        ))
    }

    async fn claim_next_logical_instance_materialization(
        &self,
        request: ClaimNextLogicalInstanceMaterialization,
    ) -> Result<LogicalInstanceMaterializationSelectionOutcome, LogicalWorkSelectionStoreError>
    {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::ClaimMaterialization);
        let mut state = self.state.lock().expect("repository state");
        state.materialization_selections += 1;
        if state.materialization.is_none()
            && let ReadyPhase::Materialization(descriptor) = state.ready.clone()
        {
            state.materialization = Some(selected_materialization(*descriptor, &request));
        }
        Ok(state.materialization.as_ref().map_or(
            LogicalInstanceMaterializationSelectionOutcome::Idle,
            |consumed| {
                LogicalInstanceMaterializationSelectionOutcome::Selected(
                    consumed.selected().clone(),
                )
            },
        ))
    }

    async fn consume_selected_logical_job_orchestration(
        &self,
        request: ConsumeSelectedLogicalJobOrchestration,
    ) -> Result<ConsumedSelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::ConsumeOrchestration);
        let mut state = self.state.lock().expect("repository state");
        state.orchestration_consumes += 1;
        let consumed = state
            .orchestration
            .as_ref()
            .expect("selected orchestration authority");
        assert_eq!(request.selected(), consumed.selected());
        let swap = state.swap_activation_reconcile
            && state.activation_renews > 0
            && matches!(
                consumed.authority(),
                ConsumedLogicalJobOrchestrationAuthority::Activation(_)
            );
        if swap {
            Ok(swapped_activation_consumed(consumed))
        } else {
            Ok(consumed.clone())
        }
    }

    async fn consume_selected_logical_instance_materialization(
        &self,
        request: ConsumeSelectedLogicalInstanceMaterialization,
    ) -> Result<ConsumedSelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError>
    {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::ConsumeMaterialization);
        let mut state = self.state.lock().expect("repository state");
        state.materialization_consumes += 1;
        let swap = std::mem::take(&mut state.swap_initial_materialization_consume);
        let consumed = state
            .materialization
            .as_ref()
            .expect("selected materialization authority");
        assert_eq!(request.selected(), consumed.selected());
        if swap {
            Ok(swapped_materialization_consumed(consumed))
        } else {
            Ok(consumed.clone())
        }
    }

    async fn quarantine_logical_job_orchestration(
        &self,
        request: QuarantineLogicalJobOrchestration,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::QuarantineOrchestration);
        let mut state = self.state.lock().expect("repository state");
        assert_eq!(
            Some(request.consumed()),
            state.orchestration.as_ref(),
            "quarantine must retain the latest exact orchestration authority for {:?}",
            request.kind(),
        );
        state.orchestration_quarantines.push(request.kind());
        Ok(LogicalWorkQuarantineOutcome::Quarantined)
    }

    async fn quarantine_logical_instance_materialization(
        &self,
        request: QuarantineLogicalInstanceMaterialization,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::QuarantineMaterialization);
        let mut state = self.state.lock().expect("repository state");
        assert_eq!(
            Some(request.consumed()),
            state.materialization.as_ref(),
            "quarantine must retain the latest exact materialization authority"
        );
        state.materialization_quarantines.push(request.kind());
        Ok(LogicalWorkQuarantineOutcome::Quarantined)
    }
}

fn materialization_descriptor(
    preparation: &LogicalActivationPreparationReceipt,
    publication: &PublishLogicalJobActivation,
) -> LogicalInstanceMaterializationDescriptor {
    let descriptor = preparation.descriptor();
    let instance = publication
        .instances()
        .first()
        .expect("one activated instance");
    let target = LogicalInstanceMaterializationTarget::new(
        descriptor.target().tenant().clone(),
        descriptor.target().run_id(),
        descriptor.target().invocation_id(),
        descriptor.target().logical_job_id(),
        instance.id(),
    )
    .expect("materialization target");
    LogicalInstanceMaterializationDescriptor::new(
        target,
        descriptor.logical_key().clone(),
        instance.matrix_index(),
        instance.matrix_total(),
        instance.matrix_digest(),
        instance.workspace().to_owned(),
        instance.job_ir().clone(),
        instance.runtime_context().clone(),
        descriptor.event().clone(),
        descriptor.execution().clone(),
        descriptor.authority_profile(),
        descriptor.runtime_policy().pin().clone(),
    )
    .expect("materialization descriptor")
}

fn wrong_preparation_receipt(
    request: &BindLogicalActivationPreparation,
) -> LogicalActivationPreparationReceipt {
    let bound_at = UnixMillis::new(
        request
            .bound_at()
            .get()
            .checked_add(1)
            .expect("different binding time"),
    );
    let different = BindLogicalActivationPreparation::new(
        request.descriptor().clone(),
        request.claim().clone(),
        request.base_context().clone(),
        request.prerequisite_context().clone(),
        bound_at,
    )
    .expect("different preparation binding");
    LogicalActivationPreparationReceipt::new(&different, false)
}

fn wrong_activation_receipt(
    request: &PublishLogicalJobActivation,
) -> LogicalActivationPublicationReceipt {
    let published_at = UnixMillis::new(
        request
            .published_at()
            .get()
            .checked_add(1)
            .expect("different publication time"),
    );
    let different = PublishLogicalJobActivation::new(
        request.claim().clone(),
        request.condition_matched(),
        request.instances().to_vec(),
        published_at,
    )
    .expect("different activation publication");
    LogicalActivationPublicationReceipt::new(&different, false)
}

fn wrong_materialization_receipt(
    request: &CommitLogicalInstanceMaterialization,
) -> LogicalMaterializationReceipt {
    let exact = LogicalMaterializationReceipt::new(request, false);
    LogicalMaterializationReceipt::from_durable(
        exact.instance_id(),
        exact.job_id(),
        exact.attempt_id(),
        exact.descriptor_digest(),
        exact.runtime_policy_revision(),
        exact.runtime_policy_digest(),
        exact.requirements_digest(),
        exact.commit_digest(),
        UnixMillis::new(
            exact
                .committed_at()
                .get()
                .checked_add(1)
                .expect("different commit time"),
        ),
        false,
    )
    .expect("different materialization receipt")
}

#[async_trait]
impl LogicalActivationPreparationStore for HarnessRepository {
    async fn renew_logical_activation_preparation(
        &self,
        request: RenewLogicalActivationPreparation,
    ) -> Result<RenewedLogicalActivationPreparation, LogicalActivationPreparationStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::RenewPreparation);
        let mut state = self.state.lock().expect("repository state");
        let consumed = state
            .orchestration
            .as_ref()
            .expect("current preparation")
            .clone();
        let ConsumedLogicalJobOrchestrationAuthority::Preparation(authority) = consumed.authority()
        else {
            panic!("preparation authority")
        };
        assert_eq!(request.claim(), authority.claim());
        state.preparation_renews += 1;
        Err(LogicalActivationPreparationStoreError::Store(
            StoreError::operation(std::io::Error::other(
                "synthetic non-committing preparation renewal",
            )),
        ))
    }

    async fn bind_logical_activation_preparation(
        &self,
        request: BindLogicalActivationPreparation,
    ) -> Result<LogicalActivationPreparationReceipt, LogicalActivationPreparationStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::BindPreparation);
        let park_every_binding_attempt = {
            let mut state = self.state.lock().expect("repository state");
            state.binds.push(request.clone());
            state.park_every_binding_attempt
        };
        if park_every_binding_attempt {
            self.park_final_mutation().await;
        }
        let fault = {
            let mut state = self.state.lock().expect("repository state");
            if let Some(durable) = state.durable_binding.as_ref() {
                if durable != &request {
                    return Err(LogicalActivationPreparationStoreError::BindConflict);
                }
                return Ok(LogicalActivationPreparationReceipt::new(&request, true));
            }
            let fault = state.next_binding_fault.take();
            match fault {
                Some(FinalMutationFault::ClaimRejected) => {
                    state.orchestration = None;
                    return Err(LogicalActivationPreparationStoreError::ClaimRejected);
                }
                Some(FinalMutationFault::InvalidTarget) => {
                    state.orchestration = None;
                    return Err(LogicalActivationPreparationStoreError::InvalidTarget);
                }
                Some(FinalMutationFault::OperationBeforeCommit) => {
                    return Err(LogicalActivationPreparationStoreError::Store(
                        StoreError::operation(std::io::Error::other(
                            "synthetic non-committing preparation ambiguity",
                        )),
                    ));
                }
                _ => {}
            }
            if state.wrong_receipt == WrongReceipt::Preparation {
                return Ok(wrong_preparation_receipt(&request));
            }
            let receipt = LogicalActivationPreparationReceipt::new(&request, false);
            state.durable_binding = Some(request.clone());
            state.ready = ReadyPhase::Activation(Box::new(receipt));
            state.orchestration = None;
            fault
        };
        match fault {
            Some(FinalMutationFault::OperationAfterCommit) => Err(
                LogicalActivationPreparationStoreError::Store(StoreError::operation(
                    std::io::Error::other("synthetic committed preparation ambiguity"),
                )),
            ),
            Some(FinalMutationFault::ParkAfterCommit) => self.park_final_mutation().await,
            Some(
                FinalMutationFault::OperationBeforeCommit
                | FinalMutationFault::ClaimRejected
                | FinalMutationFault::InvalidTarget,
            ) => unreachable!("handled before commit"),
            None => Ok(LogicalActivationPreparationReceipt::new(&request, false)),
        }
    }
}

#[async_trait]
impl LogicalActivationRepository for HarnessRepository {
    async fn renew_logical_job_activation(
        &self,
        request: RenewLogicalJobActivation,
    ) -> Result<RenewedLogicalJobActivation, LogicalActivationStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::RenewActivation);
        let mut state = self.state.lock().expect("repository state");
        let consumed = state
            .orchestration
            .as_ref()
            .expect("current activation")
            .clone();
        let ConsumedLogicalJobOrchestrationAuthority::Activation(authority) = consumed.authority()
        else {
            panic!("activation authority")
        };
        assert_eq!(request.claim(), authority.claim());
        let renewal = state.activation_renews + 1;
        if state.change_activation_evidence_on_renew == Some(renewal) {
            let plan = authority.plan();
            let changed_plan = AdmissionObject::new(
                plan.digest(),
                ObjectKey::new("changed/workflow-plan.json").expect("changed plan key"),
                plan.encoded_size(),
                plan.media_type(),
            )
            .expect("changed plan evidence");
            let changed_authority = ClaimedLogicalJobActivation::new(
                authority.claim().clone(),
                authority.logical_key().clone(),
                authority.source_order(),
                authority.kind(),
                authority.execution().clone(),
                changed_plan,
                authority.event().clone(),
                true,
            )
            .expect("changed activation authority");
            state.orchestration = Some(
                ConsumedSelectedLogicalJobOrchestration::new(
                    consumed.selected().clone(),
                    ConsumedLogicalJobOrchestrationAuthority::Activation(changed_authority),
                    consumed.validated_at(),
                )
                .expect("changed consumed activation"),
            );
        }
        state.activation_renews = renewal;
        Err(LogicalActivationStoreError::Store(StoreError::operation(
            std::io::Error::other("synthetic non-committing activation renewal"),
        )))
    }

    async fn publish_logical_job_activation(
        &self,
        request: PublishLogicalJobActivation,
    ) -> Result<LogicalActivationPublicationReceipt, LogicalActivationStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::PublishActivation);
        let fault = {
            let mut state = self.state.lock().expect("repository state");
            state.publications.push(request.clone());
            if let Some(durable) = state.durable_publication.as_ref() {
                if durable != &request {
                    return Err(LogicalActivationStoreError::PublicationConflict);
                }
                return Ok(LogicalActivationPublicationReceipt::new(&request, true));
            }
            let fault = state.next_publication_fault.take();
            match fault {
                Some(FinalMutationFault::ClaimRejected) => {
                    state.orchestration = None;
                    return Err(LogicalActivationStoreError::ClaimRejected);
                }
                Some(FinalMutationFault::InvalidTarget) => {
                    state.orchestration = None;
                    return Err(LogicalActivationStoreError::InvalidTarget);
                }
                Some(FinalMutationFault::OperationBeforeCommit) => {
                    return Err(LogicalActivationStoreError::Store(StoreError::operation(
                        std::io::Error::other("synthetic non-committing activation ambiguity"),
                    )));
                }
                _ => {}
            }
            if state.wrong_receipt == WrongReceipt::Activation {
                return Ok(wrong_activation_receipt(&request));
            }
            let preparation = match &state.ready {
                ReadyPhase::Activation(preparation) => preparation.clone(),
                _ => panic!("activation-ready preparation"),
            };
            state.successful_publications += 1;
            state.durable_publication = Some(request.clone());
            state.ready = if request.instances().is_empty() {
                ReadyPhase::Done
            } else {
                ReadyPhase::Materialization(Box::new(materialization_descriptor(
                    &preparation,
                    &request,
                )))
            };
            state.orchestration = None;
            fault
        };
        match fault {
            Some(FinalMutationFault::OperationAfterCommit) => {
                Err(LogicalActivationStoreError::Store(StoreError::operation(
                    std::io::Error::other("synthetic committed activation ambiguity"),
                )))
            }
            Some(FinalMutationFault::ParkAfterCommit) => self.park_final_mutation().await,
            Some(
                FinalMutationFault::OperationBeforeCommit
                | FinalMutationFault::ClaimRejected
                | FinalMutationFault::InvalidTarget,
            ) => unreachable!("handled before commit"),
            None => Ok(LogicalActivationPublicationReceipt::new(&request, false)),
        }
    }
}

#[async_trait]
impl LogicalMaterializationRepository for HarnessRepository {
    async fn renew_logical_instance_materialization(
        &self,
        request: RenewLogicalInstanceMaterialization,
    ) -> Result<RenewedLogicalInstanceMaterialization, LogicalMaterializationStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::RenewMaterialization);
        let mut state = self.state.lock().expect("repository state");
        let consumed = state
            .materialization
            .as_ref()
            .expect("current materialization")
            .clone();
        let authority = consumed.authority();
        assert_eq!(request.claim(), authority.claim());
        state.materialization_renews += 1;
        Err(LogicalMaterializationStoreError::Store(
            StoreError::operation(std::io::Error::other(
                "synthetic non-committing materialization renewal",
            )),
        ))
    }

    async fn commit_logical_instance_materialization(
        &self,
        request: CommitLogicalInstanceMaterialization,
    ) -> Result<LogicalMaterializationReceipt, LogicalMaterializationStoreError> {
        let _call = self
            .trace
            .begin_repository(HarnessOperation::CommitMaterialization);
        let fault = {
            let mut state = self.state.lock().expect("repository state");
            state.commits.push(request.clone());
            if let Some(durable) = state.durable_commit.as_ref() {
                if durable != &request {
                    return Err(LogicalMaterializationStoreError::CommitConflict);
                }
                return Ok(LogicalMaterializationReceipt::new(&request, true));
            }
            let fault = state.next_commit_fault.take();
            match fault {
                Some(FinalMutationFault::ClaimRejected) => {
                    state.materialization = None;
                    return Err(LogicalMaterializationStoreError::ClaimRejected);
                }
                Some(FinalMutationFault::InvalidTarget) => {
                    state.materialization = None;
                    return Err(LogicalMaterializationStoreError::InvalidTarget);
                }
                Some(FinalMutationFault::OperationBeforeCommit) => {
                    return Err(LogicalMaterializationStoreError::Store(
                        StoreError::operation(std::io::Error::other(
                            "synthetic non-committing materialization ambiguity",
                        )),
                    ));
                }
                _ => {}
            }
            if state.wrong_receipt == WrongReceipt::Materialization {
                return Ok(wrong_materialization_receipt(&request));
            }
            state.durable_commit = Some(request.clone());
            state.ready = ReadyPhase::Done;
            state.materialization = None;
            fault
        };
        match fault {
            Some(FinalMutationFault::OperationAfterCommit) => Err(
                LogicalMaterializationStoreError::Store(StoreError::operation(
                    std::io::Error::other("synthetic committed materialization ambiguity"),
                )),
            ),
            Some(FinalMutationFault::ParkAfterCommit) => self.park_final_mutation().await,
            Some(
                FinalMutationFault::OperationBeforeCommit
                | FinalMutationFault::ClaimRejected
                | FinalMutationFault::InvalidTarget,
            ) => unreachable!("handled before commit"),
            None => Ok(LogicalMaterializationReceipt::new(&request, false)),
        }
    }
}

struct Harness {
    service: Arc<AutonomousWorkflowService>,
    executor: Arc<GithubAutonomousWorkflowPhaseExecutor>,
    repository: Arc<HarnessRepository>,
    blobs: Arc<FaultBlobStore>,
    clock: Arc<TestClock>,
    trace: HarnessTrace,
}

async fn new_harness() -> Harness {
    new_harness_with(WORKFLOW_SOURCE, JobAuthorityProfile::Standard, Vec::new()).await
}

async fn new_harness_with(
    source: &str,
    authority_profile: JobAuthorityProfile,
    prerequisites: Vec<LogicalActivationPrerequisiteEvidence>,
) -> Harness {
    let trace = HarnessTrace::default();
    let blobs = Arc::new(FaultBlobStore::new(trace.clone()));
    let plan = compile_plan(source);
    let logical_key = WorkflowJobKey::new("build").expect("logical key");
    let source_order = logical_job_source_order(&plan, &logical_key);
    let plan_object = put_input(
        &blobs.inner,
        "admission/v2/autonomous/plan.json",
        WORKFLOW_PLAN_MEDIA_TYPE,
        Bytes::from(serde_json::to_vec(&plan).expect("plan JSON")),
    )
    .await;
    let event_object = put_input(
        &blobs.inner,
        "admission/v2/autonomous/event.json",
        WORKFLOW_EVENT_MEDIA_TYPE,
        Bytes::from_static(br#"{"mode":"autonomous"}"#),
    )
    .await;
    let base_context_object = put_base_context(&blobs.inner, authority_profile).await;
    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id("synthetic-tenant").expect("tenant"),
        RunId::from_uuid(Uuid::from_u128(11)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(12)).expect("invocation"),
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(13)).expect("logical job"),
    )
    .expect("preparation target");
    let (runner_policy, runtime_policy) = put_runtime_policy(&blobs.inner, &target).await;
    let descriptor = LogicalActivationPreparationDescriptor::new(
        target,
        logical_key,
        source_order,
        LogicalActivationExecutionContext::new(
            WorkflowId::from_uuid(Uuid::from_u128(14)),
            "Autonomous CI".to_owned(),
            GIT_REF.to_owned(),
            "workflow_dispatch".to_owned(),
            Some("synthetic-actor".to_owned()),
            RunIdAlias::new(11).expect("run ID alias"),
            7,
            1,
        )
        .expect("execution context"),
        authority_profile,
        runner_policy,
        runtime_policy,
        plan_object,
        event_object,
        LogicalActivationBaseContextKind::Admission,
        base_context_object,
        prerequisites,
        UnixMillis::new(10),
    )
    .expect("preparation descriptor");
    let repository = Arc::new(HarnessRepository::new(descriptor, trace.clone()));
    let clock = Arc::new(TestClock::new(1_000));
    let executor = Arc::new(GithubAutonomousWorkflowPhaseExecutor::new(
        blobs.clone(),
        repository.clone(),
        repository.clone(),
        repository.clone(),
        clock.clone(),
    ));
    assert_executor_debug(&executor);
    let service = Arc::new(AutonomousWorkflowService::new(
        repository.clone(),
        repository.clone(),
        repository.clone(),
        repository.clone(),
        executor.clone(),
        clock.clone(),
        orchestration_worker(),
        materialization_worker(),
    ));
    blobs.reset_observation();
    trace.reset();
    Harness {
        service,
        executor,
        repository,
        blobs,
        clock,
        trace,
    }
}

fn assert_executor_debug(executor: &GithubAutonomousWorkflowPhaseExecutor) {
    assert_eq!(
        format!("{executor:?}"),
        "GithubAutonomousWorkflowPhaseExecutor",
        "executor Debug must expose only its type, never child ports or evidence",
    );
}

fn logical_job_source_order(plan: &WorkflowPlan, key: &WorkflowJobKey) -> u16 {
    u16::try_from(plan.job(key).expect("logical job").source_order()).expect("bounded source order")
}

fn orchestration_worker() -> LogicalActivationWorkerId {
    LogicalActivationWorkerId::from_uuid(Uuid::from_u128(20)).expect("orchestration worker")
}

fn materialization_worker() -> LogicalMaterializationWorkerId {
    LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(21)).expect("materialization worker")
}

async fn put_runtime_policy(
    blobs: &MemoryBlobStore,
    target: &LogicalActivationPreparationTarget,
) -> (AdmissionObject, PinnedWorkflowRuntimePolicy) {
    let runtime_policy =
        WorkflowRuntimePolicy::decode_configuration(RUNTIME_POLICY).expect("runtime policy");
    let canonical = runtime_policy
        .canonical_bytes()
        .expect("canonical runtime policy");
    let runner_policy = put_input(
        blobs,
        &format!(
            "github/runner-policy/v1/{}.json",
            runtime_policy.canonical_digest()
        ),
        GITHUB_RUNNER_POLICY_MEDIA_TYPE,
        Bytes::from(canonical),
    )
    .await;
    let pin = WorkflowRuntimePolicyPin::new(
        target.tenant().clone(),
        RepositoryId::from_uuid(Uuid::from_u128(16)),
        WorkflowRuntimePolicyRevision::new(1).expect("runtime policy revision"),
        runtime_policy.digest(),
    );
    let pinned = PinnedWorkflowRuntimePolicy::new(target.run_id(), pin, runtime_policy)
        .expect("pinned runtime policy");
    (runner_policy, pinned)
}

fn compile_plan(source: &str) -> automata_ci_core::WorkflowPlan {
    let provenance = SourceProvenance::new(
        SourceId::new(WORKFLOW_PATH),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(WORKFLOW_PATH),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let compiled = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id("synthetic-autonomous")
            .with_commit_sha(REVISION)
            .with_git_ref(GIT_REF),
    ));
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    compiled.into_parts().0.expect("workflow plan")
}

async fn put_input(
    blobs: &MemoryBlobStore,
    key: &str,
    media_type: &str,
    bytes: Bytes,
) -> AdmissionObject {
    let payload = BlobPayload::from_bytes(
        BlobKey::new(key).expect("blob key"),
        MediaType::new(media_type).expect("media type"),
        bytes,
    );
    let descriptor = payload.descriptor().clone();
    blobs.put_if_absent(payload).await.expect("input put");
    AdmissionObject::new(
        descriptor.digest(),
        ObjectKey::new(descriptor.key().as_str()).expect("object key"),
        descriptor.size(),
        descriptor.media_type().as_str(),
    )
    .expect("admission object")
}

fn prerequisite_evidence() -> LogicalActivationPrerequisiteEvidence {
    let outputs = vec![
        LogicalActivationPrerequisiteOutput::new(
            WorkflowOutputKey::new("public").expect("public output key"),
            OutputSensitivity::Public,
            Some("visible".to_owned()),
        )
        .expect("public prerequisite output"),
        LogicalActivationPrerequisiteOutput::new(
            WorkflowOutputKey::new("secret").expect("secret output key"),
            OutputSensitivity::SecretDerived,
            None,
        )
        .expect("secret-derived prerequisite output"),
    ];
    LogicalActivationPrerequisiteEvidence::new(
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(31)).expect("prerequisite job"),
        WorkflowJobKey::new("setup").expect("prerequisite logical key"),
        0,
        Sha256Digest::from_bytes([0x31; 32]),
        Sha256Digest::from_bytes([0x32; 32]),
        Sha256Digest::from_bytes([0x33; 32]),
        JobConclusion::Success,
        false,
        false,
        false,
        outputs,
        UnixMillis::new(9),
    )
    .expect("prerequisite evidence")
}

fn matrix_prerequisite_evidence(
    sensitivity: OutputSensitivity,
    value: Option<&str>,
) -> LogicalActivationPrerequisiteEvidence {
    let output = LogicalActivationPrerequisiteOutput::new(
        WorkflowOutputKey::new("matrix").expect("matrix output key"),
        sensitivity,
        value.map(str::to_owned),
    )
    .expect("matrix prerequisite output");
    LogicalActivationPrerequisiteEvidence::new(
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(41)).expect("prerequisite job"),
        WorkflowJobKey::new("plan").expect("prerequisite logical key"),
        0,
        Sha256Digest::from_bytes([0x41; 32]),
        Sha256Digest::from_bytes([0x42; 32]),
        Sha256Digest::from_bytes([0x43; 32]),
        JobConclusion::Success,
        false,
        false,
        false,
        vec![output],
        UnixMillis::new(9),
    )
    .expect("matrix prerequisite evidence")
}

fn admitted_base_context(authority_profile: JobAuthorityProfile) -> JobRuntimeContext {
    let inputs = ContextValue::object(BTreeMap::from([(
        "target".to_owned(),
        ContextValue::string("production"),
    )]))
    .expect("inputs");
    let vars = ContextValue::object(BTreeMap::from([(
        "channel".to_owned(),
        ContextValue::string("stable"),
    )]))
    .expect("variables");
    let secrets = match authority_profile {
        JobAuthorityProfile::Standard => {
            let secret = SecretBinding::new("grant-00000000-0000-0000-0000-000000000001")
                .expect("secret binding")
                .with_version_id("version-00000000-0000-0000-0000-000000000002")
                .expect("secret version");
            BTreeMap::from([("DEPLOY_TOKEN".to_owned(), secret)])
        }
        JobAuthorityProfile::CredentialFree => BTreeMap::new(),
    };
    JobRuntimeContext::new_base(inputs, vars, secrets).expect("admission base context")
}

async fn put_base_context(
    blobs: &MemoryBlobStore,
    authority_profile: JobAuthorityProfile,
) -> AdmissionObject {
    let context = admitted_base_context(authority_profile);
    let encoded = automata_ci_protocol_protobuf::encode_job_runtime_context(
        &context,
        &ProtocolLimits::default(),
    )
    .expect("base runtime context");
    put_input(
        blobs,
        "admission/v2/base-runtime-context/context.pb",
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
        Bytes::from(encoded),
    )
    .await
}

fn admission_blob_descriptor(object: &AdmissionObject) -> BlobDescriptor {
    BlobDescriptor::new(
        BlobKey::new(object.object_key().as_str()).expect("admission blob key"),
        object.digest(),
        object.encoded_size(),
        MediaType::new(object.media_type()).expect("admission blob media type"),
    )
}

fn activation_blob_descriptor(object: &LogicalActivationObject) -> BlobDescriptor {
    BlobDescriptor::new(
        BlobKey::new(object.object_key().as_str()).expect("activation blob key"),
        object.digest(),
        object.encoded_size(),
        MediaType::new(object.media_type()).expect("activation blob media type"),
    )
}

async fn load_admission_blob(blobs: &MemoryBlobStore, object: &AdmissionObject) -> Bytes {
    blobs
        .get_verified(&admission_blob_descriptor(object), object.encoded_size())
        .await
        .expect("admission blob")
        .into_bytes()
}

async fn load_activation_blob(blobs: &MemoryBlobStore, object: &LogicalActivationObject) -> Bytes {
    blobs
        .get_verified(&activation_blob_descriptor(object), object.encoded_size())
        .await
        .expect("activation blob")
        .into_bytes()
}

async fn put_runtime_context_blob(
    blobs: &MemoryBlobStore,
    key: &str,
    bytes: Bytes,
) -> LogicalActivationObject {
    let payload = BlobPayload::from_bytes(
        BlobKey::new(key).expect("runtime-context blob key"),
        MediaType::new(JOB_RUNTIME_CONTEXT_MEDIA_TYPE).expect("runtime-context media type"),
        bytes,
    );
    let descriptor = payload.descriptor().clone();
    blobs
        .put_if_absent(payload)
        .await
        .expect("runtime-context input put");
    LogicalActivationObject::runtime_context(
        descriptor.digest(),
        ObjectKey::new(descriptor.key().as_str()).expect("runtime-context object key"),
        descriptor.size(),
    )
    .expect("runtime-context object")
}

async fn complete_preparation(harness: &Harness) {
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("preparation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
}

async fn complete_activation(harness: &Harness) {
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("activation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Activation)
    );
}

fn service_with_executor(
    harness: &Harness,
    executor: Arc<dyn AutonomousWorkflowPhaseExecutor>,
) -> Arc<AutonomousWorkflowService> {
    Arc::new(AutonomousWorkflowService::new(
        harness.repository.clone(),
        harness.repository.clone(),
        harness.repository.clone(),
        harness.repository.clone(),
        executor,
        harness.clock.clone(),
        orchestration_worker(),
        materialization_worker(),
    ))
}

#[derive(Clone)]
struct ParkAfterReadyExecutor {
    inner: Arc<GithubAutonomousWorkflowPhaseExecutor>,
    phase: AutonomousWorkflowPhase,
    parked: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ParkAfterReadyExecutor {
    fn new(
        inner: Arc<GithubAutonomousWorkflowPhaseExecutor>,
        phase: AutonomousWorkflowPhase,
    ) -> Self {
        Self {
            inner,
            phase,
            parked: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    async fn wait_until_parked(&self) {
        loop {
            let notified = self.notify.notified();
            if self.parked.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    async fn park_after_ready(
        &self,
        phase: AutonomousWorkflowPhase,
        outcome: AutonomousWorkflowExecutionOutcome,
    ) -> AutonomousWorkflowExecutionOutcome {
        if phase == self.phase && outcome == AutonomousWorkflowExecutionOutcome::FinalRequestReady {
            self.parked.store(true, Ordering::SeqCst);
            self.notify.notify_waiters();
            std::future::pending::<()>().await;
        }
        outcome
    }
}

impl std::fmt::Debug for ParkAfterReadyExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ParkAfterReadyExecutor")
    }
}

impl AutonomousWorkflowPhaseExecutor for ParkAfterReadyExecutor {
    fn execute_preparation<'a>(
        &'a self,
        lease: &'a mut AutonomousPreparationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move {
            let outcome = self
                .inner
                .execute_preparation(lease, shutdown, deadline)
                .await?;
            Ok(self
                .park_after_ready(AutonomousWorkflowPhase::Preparation, outcome)
                .await)
        })
    }

    fn execute_activation<'a>(
        &'a self,
        lease: &'a mut AutonomousActivationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move {
            let outcome = self
                .inner
                .execute_activation(lease, shutdown, deadline)
                .await?;
            Ok(self
                .park_after_ready(AutonomousWorkflowPhase::Activation, outcome)
                .await)
        })
    }

    fn execute_materialization<'a>(
        &'a self,
        lease: &'a mut AutonomousMaterializationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move {
            let outcome = self
                .inner
                .execute_materialization(lease, shutdown, deadline)
                .await?;
            Ok(self
                .park_after_ready(AutonomousWorkflowPhase::Materialization, outcome)
                .await)
        })
    }

    fn submit_preparation_final<'a>(
        &'a self,
        lease: &'a AutonomousPreparationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        self.inner.submit_preparation_final(lease)
    }

    fn submit_activation_final<'a>(
        &'a self,
        lease: &'a AutonomousActivationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        self.inner.submit_activation_final(lease)
    }

    fn submit_materialization_final<'a>(
        &'a self,
        lease: &'a AutonomousMaterializationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        self.inner.submit_materialization_final(lease)
    }
}

async fn abort_after_final_mutation_parks(harness: &Harness) {
    let service = harness.service.clone();
    let mut task = tokio::spawn(async move { service.run_once(CancellationToken::new()).await });
    tokio::select! {
        () = harness.repository.wait_for_final_mutation_to_park() => {}
        result = &mut task => panic!("final mutation returned instead of parking: {result:?}"),
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("final mutation did not reach its synthetic ambiguity boundary")
        }
    }
    task.abort();
    assert!(
        task.await
            .expect_err("parked final mutation task must be aborted")
            .is_cancelled()
    );
}

async fn abort_after_ready_parks(
    service: &Arc<AutonomousWorkflowService>,
    executor: &ParkAfterReadyExecutor,
) {
    let service = service.clone();
    let mut task = tokio::spawn(async move { service.run_once(CancellationToken::new()).await });
    tokio::select! {
        () = executor.wait_until_parked() => {}
        result = &mut task => panic!("ready final request returned instead of parking: {result:?}"),
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("final request did not reach queue-local Ready custody")
        }
    }
    task.abort();
    assert!(
        task.await
            .expect_err("ready final request task must be aborted")
            .is_cancelled()
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhaseWorkCounts {
    selection_consume: (usize, usize, usize, usize),
    renewals: (usize, usize, usize),
    blob_operations: usize,
}

fn phase_work_counts(harness: &Harness) -> PhaseWorkCounts {
    PhaseWorkCounts {
        selection_consume: harness.repository.selection_consume_counts(),
        renewals: harness.repository.renewal_counts(),
        blob_operations: harness.blobs.operations(),
    }
}

async fn gracefully_shutdown_after_final_mutation_parks(harness: &Harness) -> PhaseWorkCounts {
    let service = harness.service.clone();
    let shutdown = CancellationToken::new();
    let cancel = shutdown.clone();
    let mut task = tokio::spawn(async move { service.run(shutdown).await });
    tokio::select! {
        () = harness.repository.wait_for_final_mutation_to_park() => {}
        result = &mut task => panic!("continuous worker returned before final Store cancellation: {result:?}"),
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("continuous worker did not park its final Store operation")
        }
    }
    let counts = phase_work_counts(harness);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("graceful final Store drain is bounded")
        .expect("continuous worker task joins")
        .expect("continuous worker shuts down normally");
    counts
}

async fn wait_for_binding_attempts(repository: &HarnessRepository, expected: usize) {
    for _ in 0..100 {
        if repository.binding_attempts().len() >= expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("final Store drain did not reach {expected} binding attempts")
}

fn assert_all_binding_attempts_exact(
    attempts: &[BindLogicalActivationPreparation],
    expected: usize,
) {
    assert_eq!(attempts.len(), expected);
    assert!(
        attempts.windows(2).all(|pair| pair[0] == pair[1]),
        "every pending binding replay must preserve the full request"
    );
    assert!(
        attempts
            .windows(2)
            .all(|pair| pair[0].bound_at() == pair[1].bound_at()),
        "every pending binding replay must preserve its timestamp"
    );
}

async fn expire_after_final_mutation_parks(
    harness: &Harness,
    expected_queue: AutonomousWorkflowQueue,
) {
    let service = harness.service.clone();
    let mut task = tokio::spawn(async move { service.run_once(CancellationToken::new()).await });
    tokio::select! {
        () = harness.repository.wait_for_final_mutation_to_park() => {}
        result = &mut task => panic!("final mutation returned before its deadline: {result:?}"),
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("final mutation did not reach its synthetic ambiguity boundary")
        }
    }
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        task.await
            .expect("deadline-bounded final mutation task joins")
            .expect("expired pending final request remains retryable"),
        AutonomousWorkflowOutcome::Unavailable(expected_queue)
    );
}

async fn expire_after_ready_parks(
    service: &Arc<AutonomousWorkflowService>,
    executor: &ParkAfterReadyExecutor,
    expected_queue: AutonomousWorkflowQueue,
) {
    let service = service.clone();
    let mut task = tokio::spawn(async move { service.run_once(CancellationToken::new()).await });
    tokio::select! {
        () = executor.wait_until_parked() => {}
        result = &mut task => panic!("ready final request returned before its deadline: {result:?}"),
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("final request did not reach queue-local Ready custody")
        }
    }
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        task.await
            .expect("deadline-bounded Ready task joins")
            .expect("expired unsubmitted Ready request closes normally"),
        AutonomousWorkflowOutcome::Unavailable(expected_queue)
    );
}

async fn drain_pending_custody(harness: &Harness) {
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    harness
        .service
        .run(shutdown)
        .await
        .expect("shutdown drain settles pending final custody");
}

fn assert_exact_binding_replay(attempts: &[BindLogicalActivationPreparation]) {
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts[0] == attempts[1],
        "preparation retry must preserve the full pending binding"
    );
    assert_eq!(attempts[0].bound_at(), attempts[1].bound_at());
}

fn assert_exact_publication_replay(attempts: &[PublishLogicalJobActivation]) {
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts[0] == attempts[1],
        "activation retry must preserve the full pending publication"
    );
    assert_eq!(attempts[0].published_at(), attempts[1].published_at());
}

fn assert_exact_commit_replay(attempts: &[CommitLogicalInstanceMaterialization]) {
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts[0] == attempts[1],
        "materialization retry must preserve the full pending commit"
    );
    assert_eq!(attempts[0].committed_at(), attempts[1].committed_at());
}

#[tokio::test]
async fn real_executor_completes_all_phases_without_a_second_claim() {
    let harness = new_harness().await;

    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("preparation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_eq!(
        harness.trace.take(),
        vec![
            HarnessOperation::ClaimOrchestration,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobPut,
            HarnessOperation::RenewPreparation,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::BindPreparation,
        ],
        "preparation must verify its admitted base and write prerequisites before binding"
    );
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("activation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Activation)
    );
    assert_eq!(
        harness.trace.take(),
        vec![
            HarnessOperation::ClaimMaterialization,
            HarnessOperation::ClaimOrchestration,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobGet,
            HarnessOperation::RenewActivation,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::BlobPut,
            HarnessOperation::BlobPut,
            HarnessOperation::RenewActivation,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::PublishActivation,
        ],
        "activation must read all inputs, write runtime then JobIR, and publish last"
    );
    let publication = harness.repository.publication_attempts();
    let gate = publication[0].instances()[0]
        .environment_gate()
        .expect("activation-derived environment gate evidence");
    assert_eq!(gate.environment(), None);
    assert_eq!(gate.event_trust(), JobEventTrust::Trusted);
    assert_eq!(gate.source_kind(), JobSourceKind::SameRepository);
    assert_eq!(
        gate.reusable_secret_permission(),
        ReusableSecretPermission::None
    );
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("materialization"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_eq!(
        harness.trace.take(),
        vec![
            HarnessOperation::ClaimOrchestration,
            HarnessOperation::ClaimMaterialization,
            HarnessOperation::ConsumeMaterialization,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobGet,
            HarnessOperation::RenewMaterialization,
            HarnessOperation::ConsumeMaterialization,
            HarnessOperation::CommitMaterialization,
        ],
        "materialization must verify JobIR then runtime before its renewed-fence commit"
    );

    assert_eq!(
        harness.repository.selection_consume_counts(),
        (3, 2, 5, 2),
        "the selected path must use only selection and exact consume/reconcile calls"
    );
    assert_eq!(harness.repository.renewal_counts(), (1, 2, 1));
    assert_eq!(
        harness.repository.bind_generations(),
        vec![1],
        "the synthetic Store::Operation renewals are explicitly non-committing",
    );
    assert_eq!(harness.repository.publication_generations(), vec![1]);
    assert_eq!(harness.repository.commit_generations(), vec![1]);
    assert_eq!(harness.repository.mutation_counts(), (1, 1, 1));
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
}

#[tokio::test]
async fn all_blob_error_kinds_have_closed_retry_or_quarantine_classification() {
    for (kind, retryable) in [
        (BlobStoreErrorKind::NotFound, false),
        (BlobStoreErrorKind::Conflict, false),
        (BlobStoreErrorKind::Integrity, false),
        (BlobStoreErrorKind::TooLarge, false),
        (BlobStoreErrorKind::Unauthorized, true),
        (BlobStoreErrorKind::Unavailable, true),
        (BlobStoreErrorKind::InvalidResponse, true),
    ] {
        let harness = new_harness().await;
        harness.blobs.fail_next(kind);

        let outcome = harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("closed blob classification");
        let (orchestration, materialization) = harness.repository.quarantine_kinds();
        if retryable {
            assert_eq!(
                outcome,
                AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration),
                "{kind:?}"
            );
            assert!(orchestration.is_empty(), "{kind:?}");
        } else {
            assert_eq!(
                outcome,
                AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration),
                "{kind:?}"
            );
            assert_eq!(
                orchestration,
                vec![LogicalWorkQuarantineKind::ObjectEvidence],
                "{kind:?}"
            );
        }
        assert!(materialization.is_empty(), "{kind:?}");
        assert_eq!(harness.repository.mutation_counts(), (0, 0, 0));
        assert_eq!(harness.repository.renewal_counts(), (0, 0, 0));
    }
}

#[tokio::test]
async fn tampered_admission_base_context_is_rejected_before_derived_writes() {
    let harness = new_harness().await;
    harness.blobs.fail_next(BlobStoreErrorKind::Integrity);

    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("closed integrity classification"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(harness.blobs.operations(), 1);
    assert_eq!(harness.blobs.put_outcomes(), (0, 0));
    assert!(harness.repository.binding_attempts().is_empty());
    assert_eq!(
        harness.repository.quarantine_kinds().0,
        vec![LogicalWorkQuarantineKind::ObjectEvidence]
    );
}

#[tokio::test]
async fn cancellation_between_blob_operations_prevents_every_later_mutation() {
    for operation in 1..=2 {
        let harness = new_harness().await;
        let shutdown = CancellationToken::new();
        harness.blobs.cancel_after(operation, shutdown.clone());
        assert_eq!(
            harness
                .service
                .run_once(shutdown)
                .await
                .expect_err("preparation cancellation"),
            AutonomousWorkflowError::Shutdown
        );
        assert_eq!(harness.blobs.operations(), operation);
        assert_eq!(harness.repository.mutation_counts(), (0, 0, 0));
    }

    for operation in 1..=6 {
        let harness = new_harness().await;
        assert_eq!(
            harness
                .service
                .run_once(CancellationToken::new())
                .await
                .expect("preparation"),
            AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
        );
        harness.blobs.reset_observation();
        let shutdown = CancellationToken::new();
        harness.blobs.cancel_after(operation, shutdown.clone());
        assert_eq!(
            harness
                .service
                .run_once(shutdown)
                .await
                .expect_err("activation cancellation"),
            AutonomousWorkflowError::Shutdown
        );
        assert_eq!(harness.blobs.operations(), operation);
        assert_eq!(harness.repository.mutation_counts(), (1, 0, 0));
    }

    for operation in 1..=2 {
        let harness = new_harness().await;
        assert_eq!(
            harness
                .service
                .run_once(CancellationToken::new())
                .await
                .expect("preparation"),
            AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
        );
        assert_eq!(
            harness
                .service
                .run_once(CancellationToken::new())
                .await
                .expect("activation"),
            AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Activation)
        );
        harness.blobs.reset_observation();
        let shutdown = CancellationToken::new();
        harness.blobs.cancel_after(operation, shutdown.clone());
        assert_eq!(
            harness
                .service
                .run_once(shutdown)
                .await
                .expect_err("materialization cancellation"),
            AutonomousWorkflowError::Shutdown
        );
        assert_eq!(harness.blobs.operations(), operation);
        assert_eq!(harness.repository.mutation_counts(), (1, 1, 0));
    }
}

#[tokio::test]
async fn valid_but_wrong_final_receipts_quarantine_relational_evidence() {
    let harness = new_harness().await;
    harness
        .repository
        .set_wrong_receipt(WrongReceipt::Preparation);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("wrong preparation receipt"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(
        harness.repository.quarantine_kinds().0,
        vec![LogicalWorkQuarantineKind::RelationalEvidence]
    );

    let harness = new_harness().await;
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("preparation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    harness
        .repository
        .set_wrong_receipt(WrongReceipt::Activation);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("wrong activation receipt"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(
        harness.repository.quarantine_kinds().0,
        vec![LogicalWorkQuarantineKind::RelationalEvidence]
    );

    let harness = new_harness().await;
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("preparation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("activation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Activation)
    );
    harness
        .repository
        .set_wrong_receipt(WrongReceipt::Materialization);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("wrong materialization receipt"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Materialization)
    );
    assert_eq!(
        harness.repository.quarantine_kinds().1,
        vec![LogicalWorkQuarantineKind::RelationalEvidence]
    );
}

async fn assert_preparation_pending_evidence_settles_before_quarantine() {
    let harness = new_harness().await;
    harness
        .repository
        .fault_next_binding(FinalMutationFault::OperationBeforeCommit);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous preparation final request"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    let counts = harness.repository.selection_consume_counts();
    let renewals = harness.repository.renewal_counts();
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(harness.repository.binding_attempts().len(), 1);
    harness
        .repository
        .set_wrong_receipt(WrongReceipt::Preparation);

    drain_pending_custody(&harness).await;
    assert_exact_binding_replay(&harness.repository.binding_attempts());
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(harness.repository.selection_consume_counts(), counts);
    assert_eq!(harness.repository.renewal_counts(), renewals);

    drain_pending_custody(&harness).await;
    assert_eq!(harness.repository.binding_attempts().len(), 2);
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("settled preparation evidence quarantines on the next live pass"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(
        harness.repository.quarantine_kinds().0,
        vec![LogicalWorkQuarantineKind::RelationalEvidence]
    );
    assert_eq!(harness.repository.binding_attempts().len(), 2);
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(harness.repository.selection_consume_counts(), counts);
    assert_eq!(harness.repository.renewal_counts(), renewals);
    assert!(
        harness.trace.take().ends_with(&[
            HarnessOperation::BindPreparation,
            HarnessOperation::BindPreparation,
            HarnessOperation::QuarantineOrchestration,
        ]),
        "settled preparation evidence must quarantine without more phase work"
    );
}

async fn assert_activation_pending_evidence_settles_before_quarantine() {
    let harness = new_harness().await;
    complete_preparation(&harness).await;
    harness.blobs.reset_observation();
    harness.trace.reset();
    harness
        .repository
        .fault_next_publication(FinalMutationFault::OperationBeforeCommit);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous activation final request"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    let counts = harness.repository.selection_consume_counts();
    let renewals = harness.repository.renewal_counts();
    assert_eq!(harness.blobs.operations(), 6);
    assert_eq!(harness.repository.publication_attempts().len(), 1);
    harness
        .repository
        .set_wrong_receipt(WrongReceipt::Activation);

    drain_pending_custody(&harness).await;
    assert_exact_publication_replay(&harness.repository.publication_attempts());
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
    assert_eq!(harness.blobs.operations(), 6);
    assert_eq!(harness.repository.selection_consume_counts(), counts);
    assert_eq!(harness.repository.renewal_counts(), renewals);

    drain_pending_custody(&harness).await;
    assert_eq!(harness.repository.publication_attempts().len(), 2);
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
    assert_eq!(harness.blobs.operations(), 6);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("settled activation evidence quarantines on the next live pass"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(
        harness.repository.quarantine_kinds().0,
        vec![LogicalWorkQuarantineKind::RelationalEvidence]
    );
    assert_eq!(harness.repository.publication_attempts().len(), 2);
    assert_eq!(harness.blobs.operations(), 6);
    assert_eq!(harness.repository.selection_consume_counts(), counts);
    assert_eq!(harness.repository.renewal_counts(), renewals);
    assert!(
        harness.trace.take().ends_with(&[
            HarnessOperation::PublishActivation,
            HarnessOperation::PublishActivation,
            HarnessOperation::QuarantineOrchestration,
        ]),
        "settled activation evidence must quarantine without more phase work"
    );
}

async fn assert_materialization_pending_evidence_settles_before_quarantine() {
    let harness = new_harness().await;
    complete_preparation(&harness).await;
    complete_activation(&harness).await;
    harness.blobs.reset_observation();
    harness.trace.reset();
    harness
        .repository
        .fault_next_commit(FinalMutationFault::OperationBeforeCommit);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous materialization final request"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Materialization)
    );
    let counts = harness.repository.selection_consume_counts();
    let renewals = harness.repository.renewal_counts();
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(harness.repository.commit_attempts().len(), 1);
    harness
        .repository
        .set_wrong_receipt(WrongReceipt::Materialization);

    drain_pending_custody(&harness).await;
    assert_exact_commit_replay(&harness.repository.commit_attempts());
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(harness.repository.selection_consume_counts(), counts);
    assert_eq!(harness.repository.renewal_counts(), renewals);

    drain_pending_custody(&harness).await;
    assert_eq!(harness.repository.commit_attempts().len(), 2);
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("settled materialization evidence quarantines on the next live pass"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Materialization)
    );
    assert_eq!(
        harness.repository.quarantine_kinds().1,
        vec![LogicalWorkQuarantineKind::RelationalEvidence]
    );
    assert_eq!(harness.repository.commit_attempts().len(), 2);
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(harness.repository.selection_consume_counts(), counts);
    assert_eq!(harness.repository.renewal_counts(), renewals);
    assert!(
        harness.trace.take().ends_with(&[
            HarnessOperation::CommitMaterialization,
            HarnessOperation::CommitMaterialization,
            HarnessOperation::QuarantineMaterialization,
        ]),
        "settled materialization evidence must quarantine without more phase work"
    );
}

#[tokio::test]
async fn drained_final_evidence_settles_before_next_live_quarantine() {
    assert_preparation_pending_evidence_settles_before_quarantine().await;
    assert_activation_pending_evidence_settles_before_quarantine().await;
    assert_materialization_pending_evidence_settles_before_quarantine().await;
}

#[tokio::test]
async fn renewal_rejects_an_a_to_b_consume_response_before_more_io() {
    let harness = new_harness().await;
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("preparation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    harness.blobs.reset_observation();
    harness.repository.swap_activation_reconcile();

    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect_err("replacement selection must be rejected"),
        AutonomousWorkflowError::AuthorityRejected
    );
    assert_eq!(harness.blobs.operations(), 4);
    assert_eq!(harness.repository.mutation_counts(), (1, 0, 0));
    assert_eq!(harness.repository.renewal_counts(), (1, 1, 0));
}

#[tokio::test]
async fn activation_rechecks_immutable_evidence_after_each_renewal() {
    for (renewal, expected_blob_operations) in [(1, 4), (2, 6)] {
        let harness = new_harness().await;
        assert_eq!(
            harness
                .service
                .run_once(CancellationToken::new())
                .await
                .expect("preparation"),
            AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
        );
        harness.blobs.reset_observation();
        harness
            .repository
            .change_activation_evidence_on_renew(renewal);

        let outcome = harness
            .service
            .run_once(CancellationToken::new())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "changed evidence classification: {error:?}; selection/consume={:?}; renewals={:?}; mutations={:?}; blob_operations={}",
                    harness.repository.selection_consume_counts(),
                    harness.repository.renewal_counts(),
                    harness.repository.mutation_counts(),
                    harness.blobs.operations(),
                )
            });
        assert_eq!(
            outcome,
            AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
        );
        assert_eq!(harness.blobs.operations(), expected_blob_operations);
        assert_eq!(harness.repository.mutation_counts(), (1, 0, 0));
        assert_eq!(harness.repository.renewal_counts(), (1, renewal, 0));
        assert_eq!(
            harness.repository.quarantine_kinds().0,
            vec![LogicalWorkQuarantineKind::RelationalEvidence]
        );
    }
}

#[tokio::test]
async fn preparation_hydrates_admitted_base_and_classified_prerequisites() {
    let harness = new_harness_with(
        WORKFLOW_WITH_NEEDS_SOURCE,
        JobAuthorityProfile::Standard,
        vec![prerequisite_evidence()],
    )
    .await;

    complete_preparation(&harness).await;

    let binding = harness.repository.last_binding();
    assert_eq!(
        binding.base_context().media_type(),
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE
    );
    assert_eq!(
        binding.prerequisite_context().media_type(),
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE
    );
    let limits = ProtocolLimits::default();
    let base_bytes = load_admission_blob(&harness.blobs.inner, binding.base_context()).await;
    let base = automata_ci_protocol_protobuf::decode_job_runtime_context(&base_bytes, &limits)
        .expect("base runtime context");
    assert_eq!(
        base.inputs()
            .as_object()
            .and_then(|inputs| inputs.get("target"))
            .and_then(ContextValue::as_string),
        Some("production"),
    );
    assert_eq!(
        base.vars()
            .as_object()
            .and_then(|vars| vars.get("channel"))
            .and_then(ContextValue::as_string),
        Some("stable"),
    );
    assert!(
        base.matrix()
            .as_object()
            .is_some_and(std::collections::BTreeMap::is_empty)
    );
    assert!(base.needs().is_empty());
    let secret_binding = base.secrets().get("DEPLOY_TOKEN").expect("secret locator");
    assert_eq!(
        secret_binding.binding_id(),
        "grant-00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(
        secret_binding.version_id(),
        Some("version-00000000-0000-0000-0000-000000000002")
    );
    let debug = format!("{base:?}");
    for redacted in [
        "production",
        "stable",
        secret_binding.binding_id(),
        secret_binding.version_id().unwrap(),
    ] {
        assert!(!debug.contains(redacted), "Debug exposed {redacted}");
    }

    let prerequisite_bytes =
        load_admission_blob(&harness.blobs.inner, binding.prerequisite_context()).await;
    let prerequisites =
        automata_ci_protocol_protobuf::decode_job_runtime_context(&prerequisite_bytes, &limits)
            .expect("prerequisite runtime context");
    let setup = prerequisites.needs().get("setup").expect("direct need");
    assert_eq!(setup.result(), JobConclusion::Success);
    assert_eq!(
        setup
            .outputs()
            .get("public")
            .expect("public prerequisite output")
            .public_value(),
        Some("visible")
    );
    let secret = setup
        .outputs()
        .get("secret")
        .expect("secret-derived prerequisite output");
    assert_eq!(secret.sensitivity(), OutputSensitivity::SecretDerived);
    assert!(secret.expose_value().is_empty());
    assert_eq!(secret.public_value(), None);

    assert_merged_runtime_context(&harness, &base, &limits).await;
}

async fn assert_merged_runtime_context(
    harness: &Harness,
    base: &JobRuntimeContext,
    limits: &ProtocolLimits,
) {
    complete_activation(harness).await;
    let publications = harness.repository.publication_attempts();
    let instance = publications
        .last()
        .and_then(|publication| publication.instances().first())
        .expect("activated instance");
    let runtime_bytes =
        load_activation_blob(&harness.blobs.inner, instance.runtime_context()).await;
    let runtime = automata_ci_protocol_protobuf::decode_job_runtime_context(&runtime_bytes, limits)
        .expect("merged instance runtime context");
    assert_eq!(runtime.inputs(), base.inputs());
    assert_eq!(runtime.vars(), base.vars());
    assert_eq!(runtime.secrets(), base.secrets());
    let setup = runtime.needs().get("setup").expect("merged direct need");
    assert_eq!(setup.result(), JobConclusion::Success);
    assert_eq!(
        setup
            .outputs()
            .get("public")
            .expect("merged public output")
            .public_value(),
        Some("visible")
    );
    assert!(
        !setup.outputs().contains_key("secret"),
        "unreferenced secret-derived output metadata must not expand runtime exposure"
    );
}

#[derive(Debug, Eq, PartialEq)]
struct DurableMatrixInstanceSnapshot {
    id: LogicalWorkflowInstanceId,
    index: u32,
    total: u32,
    matrix_digest: Sha256Digest,
    job_ir_digest: Sha256Digest,
    runtime_context_digest: Sha256Digest,
}

#[derive(Debug, Eq, PartialEq)]
struct OutputDrivenMatrixSnapshot {
    instances: Vec<DurableMatrixInstanceSnapshot>,
    contexts: Vec<JobRuntimeContext>,
}

async fn output_driven_matrix_snapshot() -> OutputDrivenMatrixSnapshot {
    let harness = new_harness_with(
        OUTPUT_DRIVEN_MATRIX_SOURCE,
        JobAuthorityProfile::Standard,
        vec![matrix_prerequisite_evidence(
            OutputSensitivity::Public,
            Some(OUTPUT_DRIVEN_MATRIX_VALUE),
        )],
    )
    .await;
    complete_preparation(&harness).await;
    complete_activation(&harness).await;

    let publications = harness.repository.publication_attempts();
    let publication = publications.last().expect("activation publication");
    assert!(publication.condition_matched());
    let instances = publication
        .instances()
        .iter()
        .map(|instance| DurableMatrixInstanceSnapshot {
            id: instance.id(),
            index: instance.matrix_index(),
            total: instance.matrix_total(),
            matrix_digest: instance.matrix_digest(),
            job_ir_digest: instance.job_ir().digest(),
            runtime_context_digest: instance.runtime_context().digest(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        instances
            .iter()
            .map(|instance| (instance.index, instance.total))
            .collect::<Vec<_>>(),
        [(0, 4), (1, 4), (2, 4), (3, 4)]
    );

    let mut contexts = Vec::with_capacity(publication.instances().len());
    for instance in publication.instances() {
        let bytes = load_activation_blob(&harness.blobs.inner, instance.runtime_context()).await;
        contexts.push(
            automata_ci_protocol_protobuf::decode_job_runtime_context(
                &bytes,
                &ProtocolLimits::default(),
            )
            .expect("published runtime context"),
        );
    }
    OutputDrivenMatrixSnapshot {
        instances,
        contexts,
    }
}

fn assert_matrix_order_and_public_need(contexts: &[JobRuntimeContext]) {
    let summaries = contexts
        .iter()
        .map(|context| {
            let matrix = context.matrix().as_object().expect("matrix object");
            let profile = matrix
                .get("profile")
                .and_then(ContextValue::as_object)
                .expect("profile object");
            (
                profile
                    .get("name")
                    .and_then(ContextValue::as_string)
                    .expect("profile name"),
                matrix
                    .get("shard")
                    .and_then(ContextValue::as_number)
                    .expect("matrix shard"),
                matrix.contains_key("settings"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        summaries,
        [
            ("stable", 1.0, true),
            ("preview", 1.0, false),
            ("preview", 2.0, false),
            ("edge", 3.0, true),
        ]
    );

    for context in contexts {
        assert_eq!(
            context
                .needs()
                .get("plan")
                .and_then(|need| need.outputs().get("matrix"))
                .and_then(automata_ci_core::NeedOutput::public_value),
            Some(OUTPUT_DRIVEN_MATRIX_VALUE)
        );
    }
}

fn assert_composite_matrix_values(contexts: &[JobRuntimeContext]) {
    let first_matrix = contexts[0].matrix().as_object().expect("first matrix");
    let first_profile = first_matrix
        .get("profile")
        .and_then(ContextValue::as_object)
        .expect("first profile");
    let first_options = first_profile
        .get("options")
        .and_then(ContextValue::as_array)
        .expect("first options");
    assert_eq!(first_options[0].as_string(), Some("fast"));
    assert_eq!(first_options[1].as_boolean(), Some(true));
    assert_eq!(
        first_profile
            .get("metadata")
            .and_then(ContextValue::as_object)
            .and_then(|metadata| metadata.get("tier"))
            .and_then(ContextValue::as_string),
        Some("primary")
    );
    let first_settings = first_matrix
        .get("settings")
        .and_then(ContextValue::as_object)
        .expect("merged include settings");
    assert_eq!(
        first_settings
            .get("retry")
            .and_then(ContextValue::as_number),
        Some(3.0)
    );
    assert_eq!(
        first_settings
            .get("enabled")
            .and_then(ContextValue::as_boolean),
        Some(true)
    );

    let last_matrix = contexts[3].matrix().as_object().expect("last matrix");
    assert!(
        last_matrix
            .get("profile")
            .and_then(ContextValue::as_object)
            .and_then(|profile| profile.get("options"))
            .and_then(ContextValue::as_array)
            .is_some_and(<[_]>::is_empty)
    );
    assert_eq!(
        last_matrix
            .get("settings")
            .and_then(ContextValue::as_object)
            .and_then(|settings| settings.get("enabled"))
            .and_then(ContextValue::as_boolean),
        Some(false)
    );
}

#[tokio::test]
async fn public_need_output_drives_deterministic_durable_matrix_expansion() {
    let first = output_driven_matrix_snapshot().await;
    let second = output_driven_matrix_snapshot().await;
    assert_eq!(first, second);
    assert_matrix_order_and_public_need(&first.contexts);
    assert_composite_matrix_values(&first.contexts);
}

#[tokio::test]
async fn invalid_or_secret_derived_matrix_outputs_quarantine_without_publication() {
    for (sensitivity, value) in [
        (OutputSensitivity::Public, Some("not valid JSON")),
        (OutputSensitivity::SecretDerived, None),
    ] {
        let harness = new_harness_with(
            OUTPUT_DRIVEN_MATRIX_SOURCE,
            JobAuthorityProfile::Standard,
            vec![matrix_prerequisite_evidence(sensitivity, value)],
        )
        .await;
        complete_preparation(&harness).await;

        assert_eq!(
            harness
                .service
                .run_once(CancellationToken::new())
                .await
                .expect("invalid matrix classification"),
            AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
        );
        assert!(harness.repository.publication_attempts().is_empty());
        assert_eq!(harness.repository.successful_publications(), 0);
        assert_eq!(harness.repository.mutation_counts(), (1, 0, 0));
        assert_eq!(
            harness.repository.quarantine_kinds().0,
            vec![LogicalWorkQuarantineKind::PayloadEvidence]
        );
    }
}

#[tokio::test]
async fn bounded_matrix_projects_credential_free_job_ir_for_every_instance() {
    let harness = new_harness_with(
        MATRIX_CREDENTIAL_FREE_SOURCE,
        JobAuthorityProfile::CredentialFree,
        Vec::new(),
    )
    .await;
    complete_preparation(&harness).await;
    harness.blobs.reset_observation();
    harness.trace.reset();

    complete_activation(&harness).await;

    let publications = harness.repository.publication_attempts();
    let publication = publications.last().expect("activation publication");
    assert!(publication.condition_matched());
    assert_eq!(publication.instances().len(), 2);
    assert_eq!(
        publication
            .instances()
            .iter()
            .map(automata_ci_store::ActivatedLogicalInstanceDescriptor::matrix_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert!(
        publication
            .instances()
            .iter()
            .all(|instance| instance.matrix_total() == 2)
    );
    assert_eq!(harness.blobs.operations(), 8);
    assert_eq!(harness.blobs.put_outcomes(), (4, 0));
    assert_eq!(
        harness.repository.renewal_counts(),
        (1, 3, 0),
        "activation must checkpoint initially and after each bounded instance batch"
    );
    assert_eq!(harness.repository.successful_publications(), 1);

    for instance in publication.instances() {
        let encoded = load_activation_blob(&harness.blobs.inner, instance.job_ir()).await;
        let envelope =
            automata_ci_protocol_protobuf::decode_job_ir(&encoded, &ProtocolLimits::default())
                .expect("published JobIR");
        assert_eq!(
            envelope.job().authority_profile(),
            JobAuthorityProfile::CredentialFree
        );
        assert_eq!(
            envelope.execution().run_id_alias(),
            Some(RunIdAlias::new(11).expect("run ID alias")),
        );
        assert!(matches!(
            envelope.job().permission_request(),
            JobPermissionRequest::Mapping(grants) if grants.is_empty()
        ));
    }
}

#[tokio::test]
async fn unmatched_condition_publishes_zero_instances_without_output_blobs() {
    let harness = new_harness_with(
        ZERO_INSTANCE_SOURCE,
        JobAuthorityProfile::Standard,
        Vec::new(),
    )
    .await;
    complete_preparation(&harness).await;
    harness.blobs.reset_observation();
    harness.trace.reset();

    complete_activation(&harness).await;

    let publications = harness.repository.publication_attempts();
    let publication = publications.last().expect("zero-instance publication");
    assert!(!publication.condition_matched());
    assert!(publication.instances().is_empty());
    assert_eq!(harness.blobs.operations(), 4);
    assert_eq!(harness.blobs.put_outcomes(), (0, 0));
    assert_eq!(harness.repository.renewal_counts(), (1, 1, 0));
    assert_eq!(harness.repository.successful_publications(), 1);
    assert_eq!(harness.repository.mutation_counts(), (1, 1, 0));
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("zero-instance terminal poll"),
        AutonomousWorkflowOutcome::Idle
    );
    assert_eq!(harness.repository.mutation_counts(), (1, 1, 0));
}

#[tokio::test]
async fn malformed_and_noncanonical_runtime_contexts_quarantine_before_renewal_or_commit() {
    for noncanonical in [false, true] {
        let harness = new_harness().await;
        complete_preparation(&harness).await;
        complete_activation(&harness).await;
        let descriptor = harness.repository.ready_materialization_descriptor();
        let canonical =
            load_activation_blob(&harness.blobs.inner, descriptor.runtime_context()).await;
        let (key, corrupted) = if noncanonical {
            let mut encoded = canonical.to_vec();
            encoded.extend_from_slice(&[0xf8, 0x07, 0x01]);
            let decoded = automata_ci_protocol_protobuf::decode_job_runtime_context(
                &encoded,
                &ProtocolLimits::default(),
            )
            .expect("noncanonical fixture must remain decodable");
            assert_ne!(
                automata_ci_protocol_protobuf::encode_job_runtime_context(
                    &decoded,
                    &ProtocolLimits::default(),
                )
                .expect("canonical runtime re-encoding"),
                encoded,
                "fixture must differ only by its noncanonical wire representation"
            );
            (
                "tests/runtime-context-noncanonical.pb",
                Bytes::from(encoded),
            )
        } else {
            (
                "tests/runtime-context-malformed.pb",
                Bytes::from_static(b"not protobuf"),
            )
        };
        let runtime = put_runtime_context_blob(&harness.blobs.inner, key, corrupted).await;
        harness.repository.replace_ready_runtime_context(runtime);
        harness.blobs.reset_observation();
        harness.trace.reset();

        assert_eq!(
            harness
                .service
                .run_once(CancellationToken::new())
                .await
                .expect("closed runtime-context classification"),
            AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Materialization),
            "noncanonical={noncanonical}"
        );
        assert_eq!(harness.blobs.operations(), 2, "noncanonical={noncanonical}");
        assert_eq!(
            harness.repository.renewal_counts().2,
            0,
            "runtime evidence must fail before renewal; noncanonical={noncanonical}"
        );
        assert_eq!(harness.repository.mutation_counts(), (1, 1, 0));
        assert_eq!(
            harness.repository.quarantine_kinds().1,
            vec![LogicalWorkQuarantineKind::PayloadEvidence],
            "noncanonical={noncanonical}"
        );
        assert_eq!(
            harness.trace.take(),
            vec![
                HarnessOperation::ClaimOrchestration,
                HarnessOperation::ClaimMaterialization,
                HarnessOperation::ConsumeMaterialization,
                HarnessOperation::BlobGet,
                HarnessOperation::BlobGet,
                HarnessOperation::QuarantineMaterialization,
            ],
            "noncanonical={noncanonical}"
        );
    }
}

#[tokio::test]
async fn built_ready_requests_survive_task_drop_without_repeating_phase_work() {
    let preparation = new_harness().await;
    let preparation_executor = ParkAfterReadyExecutor::new(
        preparation.executor.clone(),
        AutonomousWorkflowPhase::Preparation,
    );
    let preparation_service =
        service_with_executor(&preparation, Arc::new(preparation_executor.clone()));
    abort_after_ready_parks(&preparation_service, &preparation_executor).await;
    let preparation_counts = preparation.repository.selection_consume_counts();
    let preparation_renewals = preparation.repository.renewal_counts();
    assert_eq!(preparation.repository.mutation_counts(), (0, 0, 0));
    assert_eq!(preparation.blobs.operations(), 2);
    assert_eq!(
        preparation_service
            .run_once(CancellationToken::new())
            .await
            .expect("retained preparation Ready request"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_eq!(preparation.blobs.operations(), 2);
    assert_eq!(
        preparation.repository.selection_consume_counts(),
        preparation_counts
    );
    assert_eq!(
        preparation.repository.renewal_counts(),
        preparation_renewals
    );
    assert_eq!(preparation.repository.binding_attempts().len(), 1);

    let activation = new_harness().await;
    complete_preparation(&activation).await;
    activation.blobs.reset_observation();
    let activation_executor = ParkAfterReadyExecutor::new(
        activation.executor.clone(),
        AutonomousWorkflowPhase::Activation,
    );
    let activation_service =
        service_with_executor(&activation, Arc::new(activation_executor.clone()));
    abort_after_ready_parks(&activation_service, &activation_executor).await;
    let activation_counts = activation.repository.selection_consume_counts();
    let activation_renewals = activation.repository.renewal_counts();
    assert_eq!(activation.repository.mutation_counts(), (1, 0, 0));
    assert_eq!(activation.blobs.operations(), 6);
    assert_eq!(
        activation_service
            .run_once(CancellationToken::new())
            .await
            .expect("retained activation Ready request"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Activation)
    );
    assert_eq!(activation.blobs.operations(), 6);
    assert_eq!(
        activation.repository.selection_consume_counts(),
        activation_counts
    );
    assert_eq!(activation.repository.renewal_counts(), activation_renewals);
    assert_eq!(activation.repository.publication_attempts().len(), 1);

    let materialization = new_harness().await;
    complete_preparation(&materialization).await;
    complete_activation(&materialization).await;
    materialization.blobs.reset_observation();
    let materialization_executor = ParkAfterReadyExecutor::new(
        materialization.executor.clone(),
        AutonomousWorkflowPhase::Materialization,
    );
    let materialization_service =
        service_with_executor(&materialization, Arc::new(materialization_executor.clone()));
    abort_after_ready_parks(&materialization_service, &materialization_executor).await;
    let materialization_counts = materialization.repository.selection_consume_counts();
    let materialization_renewals = materialization.repository.renewal_counts();
    assert_eq!(materialization.repository.mutation_counts(), (1, 1, 0));
    assert_eq!(materialization.blobs.operations(), 2);
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("retained materialization Ready request"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_eq!(materialization.blobs.operations(), 2);
    assert_eq!(
        materialization.repository.selection_consume_counts(),
        materialization_counts
    );
    assert_eq!(
        materialization.repository.renewal_counts(),
        materialization_renewals
    );
    assert_eq!(materialization.repository.commit_attempts().len(), 1);
}

#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)] // Proves the same deadline boundary for all three typed final requests.
async fn expired_unpolled_ready_requests_close_without_store_submission() {
    let preparation = new_harness().await;
    let preparation_executor = ParkAfterReadyExecutor::new(
        preparation.executor.clone(),
        AutonomousWorkflowPhase::Preparation,
    );
    let preparation_service =
        service_with_executor(&preparation, Arc::new(preparation_executor.clone()));
    expire_after_ready_parks(
        &preparation_service,
        &preparation_executor,
        AutonomousWorkflowQueue::Orchestration,
    )
    .await;
    let preparation_counts = preparation.repository.selection_consume_counts();
    let preparation_renewals = preparation.repository.renewal_counts();
    assert_eq!(preparation.repository.mutation_counts(), (0, 0, 0));
    assert_eq!(preparation.blobs.operations(), 2);
    preparation.trace.take();
    assert_eq!(
        preparation_service
            .run_once(CancellationToken::new())
            .await
            .expect("expired preparation Ready custody closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(preparation.repository.mutation_counts(), (0, 0, 0));
    assert_eq!(preparation.blobs.operations(), 2);
    assert_eq!(
        preparation.repository.selection_consume_counts(),
        preparation_counts
    );
    assert_eq!(
        preparation.repository.renewal_counts(),
        preparation_renewals
    );
    assert!(preparation.trace.take().is_empty());

    let activation = new_harness().await;
    complete_preparation(&activation).await;
    activation.blobs.reset_observation();
    activation.trace.reset();
    let activation_executor = ParkAfterReadyExecutor::new(
        activation.executor.clone(),
        AutonomousWorkflowPhase::Activation,
    );
    let activation_service =
        service_with_executor(&activation, Arc::new(activation_executor.clone()));
    expire_after_ready_parks(
        &activation_service,
        &activation_executor,
        AutonomousWorkflowQueue::Orchestration,
    )
    .await;
    let activation_counts = activation.repository.selection_consume_counts();
    let activation_renewals = activation.repository.renewal_counts();
    assert_eq!(activation.repository.mutation_counts(), (1, 0, 0));
    assert_eq!(activation.blobs.operations(), 6);
    activation.trace.take();
    assert_eq!(
        activation_service
            .run_once(CancellationToken::new())
            .await
            .expect("expired activation Ready custody closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(activation.repository.mutation_counts(), (1, 0, 0));
    assert_eq!(activation.blobs.operations(), 6);
    assert_eq!(
        activation.repository.selection_consume_counts(),
        activation_counts
    );
    assert_eq!(activation.repository.renewal_counts(), activation_renewals);
    assert!(activation.trace.take().is_empty());

    let materialization = new_harness().await;
    complete_preparation(&materialization).await;
    complete_activation(&materialization).await;
    materialization.blobs.reset_observation();
    materialization.trace.reset();
    let materialization_executor = ParkAfterReadyExecutor::new(
        materialization.executor.clone(),
        AutonomousWorkflowPhase::Materialization,
    );
    let materialization_service =
        service_with_executor(&materialization, Arc::new(materialization_executor.clone()));
    expire_after_ready_parks(
        &materialization_service,
        &materialization_executor,
        AutonomousWorkflowQueue::Materialization,
    )
    .await;
    let materialization_counts = materialization.repository.selection_consume_counts();
    let materialization_renewals = materialization.repository.renewal_counts();
    assert_eq!(materialization.repository.mutation_counts(), (1, 1, 0));
    assert_eq!(materialization.blobs.operations(), 2);
    materialization.trace.take();
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("expired materialization Ready custody closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Materialization)
    );
    assert_eq!(materialization.repository.mutation_counts(), (1, 1, 0));
    assert_eq!(materialization.blobs.operations(), 2);
    assert_eq!(
        materialization.repository.selection_consume_counts(),
        materialization_counts
    );
    assert_eq!(
        materialization.repository.renewal_counts(),
        materialization_renewals
    );
    assert!(materialization.trace.take().is_empty());
}

#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)] // Proves exact expired Pending replay for all three typed final requests.
async fn expired_polled_final_requests_exactly_replay_without_phase_work() {
    let preparation = new_harness().await;
    preparation
        .repository
        .fault_next_binding(FinalMutationFault::ParkAfterCommit);
    expire_after_final_mutation_parks(&preparation, AutonomousWorkflowQueue::Orchestration).await;
    let preparation_counts = preparation.repository.selection_consume_counts();
    let preparation_renewals = preparation.repository.renewal_counts();
    complete_preparation(&preparation).await;
    assert_eq!(preparation.blobs.operations(), 2);
    assert_eq!(preparation.blobs.put_outcomes(), (1, 0));
    assert_eq!(
        preparation.repository.selection_consume_counts(),
        preparation_counts
    );
    assert_eq!(
        preparation.repository.renewal_counts(),
        preparation_renewals
    );
    assert_exact_binding_replay(&preparation.repository.binding_attempts());
    assert!(
        preparation.trace.take().ends_with(&[
            HarnessOperation::BindPreparation,
            HarnessOperation::BindPreparation,
        ]),
        "expired preparation replay must be adjacent to its first Store attempt"
    );

    let activation = new_harness().await;
    complete_preparation(&activation).await;
    activation.blobs.reset_observation();
    activation.trace.reset();
    activation
        .repository
        .fault_next_publication(FinalMutationFault::ParkAfterCommit);
    expire_after_final_mutation_parks(&activation, AutonomousWorkflowQueue::Orchestration).await;
    let activation_counts = activation.repository.selection_consume_counts();
    let activation_renewals = activation.repository.renewal_counts();
    complete_activation(&activation).await;
    assert_eq!(activation.blobs.operations(), 6);
    assert_eq!(activation.blobs.put_outcomes(), (2, 0));
    assert_eq!(
        activation.repository.selection_consume_counts(),
        activation_counts
    );
    assert_eq!(activation.repository.renewal_counts(), activation_renewals);
    assert_exact_publication_replay(&activation.repository.publication_attempts());
    assert!(
        activation.trace.take().ends_with(&[
            HarnessOperation::PublishActivation,
            HarnessOperation::PublishActivation,
        ]),
        "expired activation replay must be adjacent to its first Store attempt"
    );

    let materialization = new_harness().await;
    complete_preparation(&materialization).await;
    complete_activation(&materialization).await;
    materialization.blobs.reset_observation();
    materialization.trace.reset();
    materialization
        .repository
        .fault_next_commit(FinalMutationFault::ParkAfterCommit);
    expire_after_final_mutation_parks(&materialization, AutonomousWorkflowQueue::Materialization)
        .await;
    let materialization_counts = materialization.repository.selection_consume_counts();
    let materialization_renewals = materialization.repository.renewal_counts();
    assert_eq!(
        materialization
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("expired pending materialization commit replay"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_eq!(materialization.blobs.operations(), 2);
    assert_eq!(materialization.blobs.put_outcomes(), (0, 0));
    assert_eq!(
        materialization.repository.selection_consume_counts(),
        materialization_counts
    );
    assert_eq!(
        materialization.repository.renewal_counts(),
        materialization_renewals
    );
    assert_exact_commit_replay(&materialization.repository.commit_attempts());
    assert!(
        materialization.trace.take().ends_with(&[
            HarnessOperation::CommitMaterialization,
            HarnessOperation::CommitMaterialization,
        ]),
        "expired materialization replay must be adjacent to its first Store attempt"
    );
}

async fn assert_committed_preparation_operation_replays_exactly() {
    let preparation = new_harness().await;
    preparation
        .repository
        .fault_next_binding(FinalMutationFault::OperationAfterCommit);
    assert_eq!(
        preparation
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous preparation binding"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    let preparation_counts = preparation.repository.selection_consume_counts();
    let preparation_renewals = preparation.repository.renewal_counts();
    complete_preparation(&preparation).await;
    assert_eq!(preparation.blobs.operations(), 2);
    assert_eq!(preparation.blobs.put_outcomes(), (1, 0));
    assert_eq!(
        preparation.repository.selection_consume_counts(),
        preparation_counts
    );
    assert_eq!(
        preparation.repository.renewal_counts(),
        preparation_renewals
    );
    assert_exact_binding_replay(&preparation.repository.binding_attempts());
    assert_eq!(
        preparation.trace.take().as_slice(),
        [
            HarnessOperation::ClaimOrchestration,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobPut,
            HarnessOperation::RenewPreparation,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::BindPreparation,
            HarnessOperation::BindPreparation,
        ]
    );
}

async fn assert_committed_activation_operation_replays_exactly() {
    let activation = new_harness().await;
    complete_preparation(&activation).await;
    activation.blobs.reset_observation();
    activation.trace.reset();
    activation
        .repository
        .fault_next_publication(FinalMutationFault::OperationAfterCommit);
    assert_eq!(
        activation
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous activation publication"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    let activation_counts = activation.repository.selection_consume_counts();
    let activation_renewals = activation.repository.renewal_counts();
    complete_activation(&activation).await;
    assert_eq!(activation.blobs.operations(), 6);
    assert_eq!(activation.blobs.put_outcomes(), (2, 0));
    assert_eq!(
        activation.repository.selection_consume_counts(),
        activation_counts
    );
    assert_eq!(activation.repository.renewal_counts(), activation_renewals);
    assert_eq!(activation.repository.successful_publications(), 1);
    assert_exact_publication_replay(&activation.repository.publication_attempts());
    assert_eq!(
        &activation.trace.take()[13..],
        [
            HarnessOperation::PublishActivation,
            HarnessOperation::PublishActivation,
        ]
    );
}

async fn assert_committed_materialization_operation_replays_exactly() {
    let materialization = new_harness().await;
    complete_preparation(&materialization).await;
    complete_activation(&materialization).await;
    materialization.blobs.reset_observation();
    materialization.trace.reset();
    materialization
        .repository
        .fault_next_commit(FinalMutationFault::OperationAfterCommit);
    assert_eq!(
        materialization
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("committed materialization ambiguity"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Materialization)
    );
    let materialization_counts = materialization.repository.selection_consume_counts();
    let materialization_renewals = materialization.repository.renewal_counts();
    assert_eq!(
        materialization
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("replayed materialization commit"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_eq!(materialization.blobs.operations(), 2);
    assert_eq!(materialization.blobs.put_outcomes(), (0, 0));
    assert_eq!(
        materialization.repository.selection_consume_counts(),
        materialization_counts
    );
    assert_eq!(
        materialization.repository.renewal_counts(),
        materialization_renewals
    );
    assert_exact_commit_replay(&materialization.repository.commit_attempts());
    assert_eq!(
        &materialization.trace.take()[7..],
        [
            HarnessOperation::CommitMaterialization,
            HarnessOperation::CommitMaterialization,
        ]
    );
}

#[tokio::test]
async fn committed_store_operations_exactly_replay_without_repeating_blob_io() {
    assert_committed_preparation_operation_replays_exactly().await;
    assert_committed_activation_operation_replays_exactly().await;
    assert_committed_materialization_operation_replays_exactly().await;
}

#[tokio::test]
async fn dropped_final_store_awaits_replay_before_any_repeated_blob_io() {
    let preparation = new_harness().await;
    preparation
        .repository
        .fault_next_binding(FinalMutationFault::ParkAfterCommit);
    abort_after_final_mutation_parks(&preparation).await;
    assert_eq!(preparation.blobs.operations(), 2);
    let preparation_counts = preparation.repository.selection_consume_counts();
    let preparation_renewals = preparation.repository.renewal_counts();
    complete_preparation(&preparation).await;
    assert_eq!(preparation.blobs.operations(), 2);
    assert_eq!(preparation.blobs.put_outcomes(), (1, 0));
    assert_eq!(
        preparation.repository.selection_consume_counts(),
        preparation_counts
    );
    assert_eq!(
        preparation.repository.renewal_counts(),
        preparation_renewals
    );
    assert_exact_binding_replay(&preparation.repository.binding_attempts());

    let activation = new_harness().await;
    complete_preparation(&activation).await;
    activation.blobs.reset_observation();
    activation.trace.reset();
    activation
        .repository
        .fault_next_publication(FinalMutationFault::ParkAfterCommit);
    abort_after_final_mutation_parks(&activation).await;
    assert_eq!(activation.blobs.operations(), 6);
    let activation_counts = activation.repository.selection_consume_counts();
    let activation_renewals = activation.repository.renewal_counts();
    complete_activation(&activation).await;
    assert_eq!(activation.blobs.operations(), 6);
    assert_eq!(activation.blobs.put_outcomes(), (2, 0));
    assert_eq!(
        activation.repository.selection_consume_counts(),
        activation_counts
    );
    assert_eq!(activation.repository.renewal_counts(), activation_renewals);
    assert_exact_publication_replay(&activation.repository.publication_attempts());

    let materialization = new_harness().await;
    complete_preparation(&materialization).await;
    complete_activation(&materialization).await;
    materialization.blobs.reset_observation();
    materialization.trace.reset();
    materialization
        .repository
        .fault_next_commit(FinalMutationFault::ParkAfterCommit);
    abort_after_final_mutation_parks(&materialization).await;
    assert_eq!(materialization.blobs.operations(), 2);
    let materialization_counts = materialization.repository.selection_consume_counts();
    let materialization_renewals = materialization.repository.renewal_counts();
    assert_eq!(
        materialization
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("dropped materialization commit replay"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_eq!(materialization.blobs.operations(), 2);
    assert_eq!(materialization.blobs.put_outcomes(), (0, 0));
    assert_eq!(
        materialization.repository.selection_consume_counts(),
        materialization_counts
    );
    assert_eq!(
        materialization.repository.renewal_counts(),
        materialization_renewals
    );
    assert_exact_commit_replay(&materialization.repository.commit_attempts());
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Exercises one graceful continuous-worker shutdown per final request type.
async fn graceful_shutdown_replays_all_three_parked_final_requests() {
    let preparation = new_harness().await;
    preparation
        .repository
        .fault_next_binding(FinalMutationFault::ParkAfterCommit);
    let preparation_counts = gracefully_shutdown_after_final_mutation_parks(&preparation).await;
    assert_eq!(phase_work_counts(&preparation), preparation_counts);
    assert_eq!(preparation.blobs.operations(), 2);
    assert_exact_binding_replay(&preparation.repository.binding_attempts());
    assert!(
        preparation.trace.take().ends_with(&[
            HarnessOperation::BindPreparation,
            HarnessOperation::BindPreparation,
        ]),
        "graceful preparation drain must replay before any other work"
    );

    let activation = new_harness().await;
    complete_preparation(&activation).await;
    activation.blobs.reset_observation();
    activation.trace.reset();
    activation
        .repository
        .fault_next_publication(FinalMutationFault::ParkAfterCommit);
    let activation_counts = gracefully_shutdown_after_final_mutation_parks(&activation).await;
    assert_eq!(phase_work_counts(&activation), activation_counts);
    assert_eq!(activation.blobs.operations(), 6);
    assert_exact_publication_replay(&activation.repository.publication_attempts());
    assert!(
        activation.trace.take().ends_with(&[
            HarnessOperation::PublishActivation,
            HarnessOperation::PublishActivation,
        ]),
        "graceful activation drain must replay before any other work"
    );

    let materialization = new_harness().await;
    complete_preparation(&materialization).await;
    complete_activation(&materialization).await;
    materialization.blobs.reset_observation();
    materialization.trace.reset();
    materialization
        .repository
        .fault_next_commit(FinalMutationFault::ParkAfterCommit);
    let materialization_counts =
        gracefully_shutdown_after_final_mutation_parks(&materialization).await;
    assert_eq!(phase_work_counts(&materialization), materialization_counts);
    assert_eq!(materialization.blobs.operations(), 2);
    assert_exact_commit_replay(&materialization.repository.commit_attempts());
    assert!(
        materialization.trace.take().ends_with(&[
            HarnessOperation::CommitMaterialization,
            HarnessOperation::CommitMaterialization,
        ]),
        "graceful materialization drain must replay before any other work"
    );
}

#[tokio::test(start_paused = true)]
async fn pending_final_shutdown_drain_has_one_absolute_timeout_and_retains_exact_custody() {
    let harness = new_harness().await;
    harness.repository.park_every_binding_attempt();
    let service = harness.service.clone();
    let shutdown = CancellationToken::new();
    let cancel = shutdown.clone();
    let task = tokio::spawn(async move { service.run(shutdown).await });
    harness.repository.wait_for_final_mutation_to_park().await;
    let counts = phase_work_counts(&harness);
    assert_eq!(harness.repository.binding_attempts().len(), 1);

    cancel.cancel();
    wait_for_binding_attempts(&harness.repository, 2).await;
    for expected in 3..=FINAL_DRAIN_SUBMISSION_CAP {
        tokio::time::advance(Duration::from_millis(FINAL_DRAIN_RETRY_MILLIS)).await;
        wait_for_binding_attempts(&harness.repository, expected).await;
        assert_eq!(
            harness.repository.binding_attempts().len(),
            expected,
            "the pending final request receives one replay per cadence"
        );
    }
    tokio::time::advance(Duration::from_millis(FINAL_DRAIN_RETRY_MILLIS - 1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        harness.repository.binding_attempts().len(),
        FINAL_DRAIN_SUBMISSION_CAP,
        "no final replay starts between cadence boundaries"
    );
    assert!(!task.is_finished(), "final drain stopped before 30 seconds");
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..100 {
        if task.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(task.is_finished(), "final drain exceeded 30 seconds");
    task.await
        .expect("continuous timeout worker task joins")
        .expect("continuous timeout worker shuts down normally");
    assert_all_binding_attempts_exact(
        &harness.repository.binding_attempts(),
        FINAL_DRAIN_SUBMISSION_CAP,
    );
    assert_eq!(phase_work_counts(&harness), counts);

    harness.repository.release_binding_attempts();
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("timed-out pending binding remains replayable"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_all_binding_attempts_exact(
        &harness.repository.binding_attempts(),
        FINAL_DRAIN_SUBMISSION_CAP + 1,
    );
    assert_eq!(phase_work_counts(&harness), counts);
}

async fn assert_definitive_preparation_final_clears(fault: FinalMutationFault) {
    let harness = new_harness().await;
    harness.repository.fault_next_binding(fault);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect_err("definitive preparation final error"),
        AutonomousWorkflowError::AuthorityRejected
    );
    let counts = harness.repository.selection_consume_counts();
    let renewals = harness.repository.renewal_counts();
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(harness.repository.binding_attempts().len(), 1);

    complete_preparation(&harness).await;
    let next_counts = harness.repository.selection_consume_counts();
    let next_renewals = harness.repository.renewal_counts();
    let attempts = harness.repository.binding_attempts();
    assert!(
        next_counts.0 > counts.0 && next_counts.2 > counts.2,
        "preparation must reselect and reconsume after a definitive final error"
    );
    assert!(
        next_renewals.0 > renewals.0,
        "preparation must renew again after a definitive final error"
    );
    assert_eq!(harness.blobs.operations(), 4);
    assert_eq!(harness.blobs.put_outcomes(), (1, 1));
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts[0] != attempts[1],
        "a cleared preparation final request must not be replayed"
    );
    assert_ne!(attempts[0].bound_at(), attempts[1].bound_at());
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
}

async fn assert_definitive_activation_final_clears(fault: FinalMutationFault) {
    let harness = new_harness().await;
    complete_preparation(&harness).await;
    harness.blobs.reset_observation();
    harness.repository.fault_next_publication(fault);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect_err("definitive activation final error"),
        AutonomousWorkflowError::AuthorityRejected
    );
    let counts = harness.repository.selection_consume_counts();
    let renewals = harness.repository.renewal_counts();
    assert_eq!(harness.blobs.operations(), 6);
    assert_eq!(harness.repository.publication_attempts().len(), 1);

    complete_activation(&harness).await;
    let next_counts = harness.repository.selection_consume_counts();
    let next_renewals = harness.repository.renewal_counts();
    let attempts = harness.repository.publication_attempts();
    assert!(
        next_counts.0 > counts.0 && next_counts.2 > counts.2,
        "activation must reselect and reconsume after a definitive final error"
    );
    assert!(
        next_renewals.1 > renewals.1,
        "activation must renew again after a definitive final error"
    );
    assert_eq!(harness.blobs.operations(), 12);
    assert_eq!(harness.blobs.put_outcomes(), (2, 2));
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts[0] != attempts[1],
        "a cleared activation final request must not be replayed"
    );
    assert_ne!(attempts[0].published_at(), attempts[1].published_at());
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
}

async fn assert_definitive_materialization_final_clears(fault: FinalMutationFault) {
    let harness = new_harness().await;
    complete_preparation(&harness).await;
    complete_activation(&harness).await;
    harness.blobs.reset_observation();
    harness.repository.fault_next_commit(fault);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect_err("definitive materialization final error"),
        AutonomousWorkflowError::AuthorityRejected
    );
    let counts = harness.repository.selection_consume_counts();
    let renewals = harness.repository.renewal_counts();
    assert_eq!(harness.blobs.operations(), 2);
    assert_eq!(harness.repository.commit_attempts().len(), 1);

    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect("materialization reselects after definitive final error"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    let next_counts = harness.repository.selection_consume_counts();
    let next_renewals = harness.repository.renewal_counts();
    let attempts = harness.repository.commit_attempts();
    assert!(
        next_counts.1 > counts.1 && next_counts.3 > counts.3,
        "materialization must reselect and reconsume after a definitive final error"
    );
    assert!(
        next_renewals.2 > renewals.2,
        "materialization must renew again after a definitive final error"
    );
    assert_eq!(harness.blobs.operations(), 4);
    assert_eq!(harness.blobs.put_outcomes(), (0, 0));
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts[0] != attempts[1],
        "a cleared materialization final request must not be replayed"
    );
    assert_ne!(attempts[0].committed_at(), attempts[1].committed_at());
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
}

#[tokio::test]
async fn definitive_final_errors_clear_custody_before_next_live_selection() {
    for fault in [
        FinalMutationFault::ClaimRejected,
        FinalMutationFault::InvalidTarget,
    ] {
        assert_definitive_preparation_final_clears(fault).await;
        assert_definitive_activation_final_clears(fault).await;
        assert_definitive_materialization_final_clears(fault).await;
    }
}

#[tokio::test]
async fn stale_publication_fence_fails_closed_only_after_blob_writes() {
    let harness = new_harness().await;
    complete_preparation(&harness).await;
    harness.blobs.reset_observation();
    harness.trace.reset();
    harness
        .repository
        .fault_next_publication(FinalMutationFault::ClaimRejected);
    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect_err("stale publication fence"),
        AutonomousWorkflowError::AuthorityRejected
    );
    assert_eq!(harness.blobs.operations(), 6);
    assert_eq!(harness.blobs.put_outcomes(), (2, 0));
    assert_eq!(harness.repository.successful_publications(), 0);
    assert_eq!(harness.repository.publication_attempts().len(), 1);
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
    assert_eq!(
        harness.trace.take(),
        vec![
            HarnessOperation::ClaimMaterialization,
            HarnessOperation::ClaimOrchestration,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobGet,
            HarnessOperation::BlobGet,
            HarnessOperation::RenewActivation,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::BlobPut,
            HarnessOperation::BlobPut,
            HarnessOperation::RenewActivation,
            HarnessOperation::ConsumeOrchestration,
            HarnessOperation::PublishActivation,
        ]
    );
}

#[tokio::test]
async fn initial_materialization_consume_mismatch_is_rejected_before_blob_io() {
    let harness = new_harness().await;
    complete_preparation(&harness).await;
    complete_activation(&harness).await;
    harness.blobs.reset_observation();
    harness.trace.reset();
    harness.repository.swap_initial_materialization_consume();

    assert_eq!(
        harness
            .service
            .run_once(CancellationToken::new())
            .await
            .expect_err("replacement materialization selection must be rejected"),
        AutonomousWorkflowError::AuthorityRejected
    );
    assert_eq!(harness.blobs.operations(), 0);
    assert_eq!(harness.repository.renewal_counts(), (1, 2, 0));
    assert_eq!(harness.repository.mutation_counts(), (1, 1, 0));
    assert_eq!(harness.repository.quarantine_kinds(), (vec![], vec![]));
    assert_eq!(
        harness.trace.take(),
        vec![
            HarnessOperation::ClaimOrchestration,
            HarnessOperation::ClaimMaterialization,
            HarnessOperation::ConsumeMaterialization,
        ]
    );
}
