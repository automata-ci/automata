use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use automata_ci::server::{GithubProviderBootstrapPlan, GithubProviderConfig, SecretSource};
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, ImmutableBlobStore as _, MediaType, MemoryBlobStore,
};
use automata_ci_core::{JobAuthorityProfile, JobPermissionRequest, PermissionLevel, UnixMillis};
use automata_ci_credential_github::{
    GithubAppCredentialBroker, GithubAppCredentialConfig, GithubAppIssuer, GithubInstallationId,
};
use automata_ci_github::{
    GithubWebhookVerifier, X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256,
};
use automata_ci_github_delivery::{
    GithubDeliveryClock, GithubDeliveryPrivateRepositoryAction, GithubDeliveryRepositories,
    GithubDeliveryService, GithubDeliveryServiceConfig, GithubDeliveryServiceOutcome,
    GithubDeliverySourceCredential, GithubDeliverySourceCredentialBinding,
    GithubDeliverySourceCredentialProvider, GithubDeliverySourceCredentialProviderError,
    GithubDeliverySourceCredentialRequest, GithubDeliveryWorkerConfig, GithubDeliveryWorkerOutcome,
    GithubDeliveryWorkflowAdmissionProcessor, GithubServerServiceCredentialRelease,
};
use automata_ci_postgres::test_support::{
    PostgresTestDatabase as TestDatabase, TestResult, run_with_database,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_scm::{
    ArchiveFormat, ExactRevision, RepositoryId as ScmRepositoryId, RepositorySource,
    RepositorySourcePort, RepositorySourceRequest, ScmError, ScmProviderId,
};
use automata_ci_store::{
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, ConsumedSelectedLogicalInstanceMaterialization,
    ConsumedSelectedLogicalJobOrchestration, GithubProviderManifest,
    GithubProviderManifestRepository as _, GithubServerServiceHandoffId,
    GithubServerServiceRevision, GithubSubjectEvidenceRepository as _,
    LogicalActivationPreparationStore, LogicalActivationRepository, LogicalActivationWorkerId,
    LogicalInstanceMaterializationSelectionOutcome, LogicalJobOrchestrationSelectionOutcome,
    LogicalMaterializationRepository, LogicalMaterializationWorkerId, LogicalWorkQuarantineOutcome,
    LogicalWorkSelectionRepository, LogicalWorkSelectionStoreError, ProviderDeliveryClaimOwnerId,
    ProviderRepositoryVisibility, QuarantineLogicalInstanceMaterialization,
    QuarantineLogicalJobOrchestration, TenantScope,
};
use automata_ci_workflow_service::{
    AdmissionClock, AutonomousActivationLease, AutonomousMaterializationLease,
    AutonomousPreparationLease, AutonomousWorkflowDeadline, AutonomousWorkflowExecutionFuture,
    AutonomousWorkflowOutcome, AutonomousWorkflowPhase, AutonomousWorkflowPhaseExecutor,
    AutonomousWorkflowService, GithubAutonomousWorkflowPhaseExecutor, GithubWorkflowPlanVerifier,
    SystemAdmissionClock, WorkflowAdmissionService,
};
use axum::http::{HeaderMap, HeaderValue};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use ring::hmac;
use serde_json::{Value, json};
use sqlx::{PgPool, Row as _, postgres::PgRow};
use tar::{Builder, EntryType, Header};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const WEBHOOK_SECRET: &[u8] = b"automata-provider-matrix-webhook-secret";
const SOURCE_TOKEN: &str = "automata-provider-matrix-private-source-token";
const BEFORE_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const AFTER_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_PATH: &str = ".ci/workflows/ci.yml";

const ACTIVATION_RENEWAL_LINEAGE_QUERY: &str = r"
    SELECT repository.owner, repository.name, job.id AS logical_job_id,
           job.activation_origin_selection_id,
           job.activation_fence AS current_activation_generation,
           job.activation_input_digest AS current_activation_input_digest,
           job.runtime_policy_revision AS job_runtime_policy_revision,
           job.runtime_policy_digest AS job_runtime_policy_digest,
           selection.selection_id, selection.owner_id AS selection_owner_id,
           selection.generation AS selection_generation,
           selection.authority_digest AS selection_authority_digest,
           selection.claimed_at_ms AS selection_claimed_at_ms,
           selection.expires_at_ms AS selection_expires_at_ms,
           selection.outcome AS selection_outcome,
           selection.authority_kind AS selection_authority_kind,
           renewal.selection_id AS renewal_selection_id,
           renewal.owner_id AS renewal_owner_id,
           renewal.authority_digest AS renewal_authority_digest,
           renewal.predecessor_generation,
           renewal.predecessor_claimed_at_ms,
           renewal.predecessor_expires_at_ms,
           renewal.requested_duration_ms,
           renewal.successor_generation,
           renewal.successor_claimed_at_ms,
           renewal.successor_expires_at_ms,
           renewal.validated_at_ms,
           renewal.runtime_policy_revision AS renewal_runtime_policy_revision,
           renewal.runtime_policy_digest AS renewal_runtime_policy_digest,
           publication.activation_input_digest AS publication_input_digest,
           publication.activation_owner_id AS publication_owner_id,
           publication.activation_generation AS publication_generation,
           publication.activation_claimed_at_ms AS publication_claimed_at_ms,
           publication.activation_expires_at_ms AS publication_expires_at_ms,
           publication.runtime_policy_revision AS publication_runtime_policy_revision,
           publication.runtime_policy_digest AS publication_runtime_policy_digest,
           (
               SELECT COUNT(*)
               FROM logical_workflow_activation_work_selections AS all_selection
               WHERE all_selection.run_id = job.run_id
                 AND all_selection.invocation_id = job.invocation_id
                 AND all_selection.logical_job_id = job.id
                 AND all_selection.authority_kind = 'activation'
           ) AS activation_selection_count,
           (
               SELECT COUNT(*)
               FROM logical_workflow_activation_renewal_receipts AS all_renewal
               WHERE all_renewal.logical_job_id = job.id
                 AND all_renewal.authority_kind = 'activation'
           ) AS activation_renewal_count,
           (
               SELECT COUNT(*)
               FROM logical_workflow_activation_renewal_receipts AS later_renewal
               WHERE later_renewal.logical_job_id = job.id
                 AND later_renewal.authority_kind = 'activation'
                 AND later_renewal.successor_generation >= 3
           ) AS later_activation_renewal_count
    FROM logical_workflow_jobs AS job
    JOIN workflow_runs AS run ON run.id = job.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN logical_workflow_activation_work_selections AS selection
      ON selection.selection_id = job.activation_origin_selection_id
    JOIN logical_workflow_activation_renewal_receipts AS renewal
      ON renewal.logical_job_id = job.id
     AND renewal.authority_kind = 'activation'
    JOIN logical_workflow_activation_publications AS publication
      ON publication.run_id = job.run_id
     AND publication.invocation_id = job.invocation_id
     AND publication.logical_job_id = job.id
    ORDER BY repository.owner, repository.name
";

const STANDARD_WORKFLOW: &[u8] = b"name: Matrix Standard\non: push\njobs:\n  build:\n    runs-on: Ubuntu-24.04\n    steps:\n      - run: echo standard\n";
const CREDENTIAL_FREE_WORKFLOW: &[u8] = b"name: Matrix Credential Free\non: push\npermissions: {}\njobs:\n  build:\n    runs-on: Ubuntu-24.04\n    steps:\n      - run: echo credential-free\n";

const RUNNER_POLICY_CONFIGURATION: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24.04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"contents":"read"},"write_all":{"contents":"write"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

#[derive(Clone, Copy, Debug)]
struct MatrixCase {
    tenant: &'static str,
    connection_id: u128,
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    repository: &'static str,
    visibility: ProviderRepositoryVisibility,
    authority_profile: JobAuthorityProfile,
    checks_authority_id: u128,
    private_source_authority_id: Option<u128>,
}

const MATRIX: [MatrixCase; 4] = [
    MatrixCase {
        tenant: "matrix-public-credential-free",
        connection_id: 0x301,
        installation_id: 301,
        repository_id: 401,
        repository_owner_id: 501,
        repository: "octo/public-credential-free",
        visibility: ProviderRepositoryVisibility::Public,
        authority_profile: JobAuthorityProfile::CredentialFree,
        checks_authority_id: 0x601,
        private_source_authority_id: None,
    },
    MatrixCase {
        tenant: "matrix-public-standard",
        connection_id: 0x302,
        installation_id: 302,
        repository_id: 402,
        repository_owner_id: 502,
        repository: "octo/public-standard",
        visibility: ProviderRepositoryVisibility::Public,
        authority_profile: JobAuthorityProfile::Standard,
        checks_authority_id: 0x602,
        private_source_authority_id: None,
    },
    MatrixCase {
        tenant: "matrix-private-credential-free",
        connection_id: 0x303,
        installation_id: 303,
        repository_id: 403,
        repository_owner_id: 503,
        repository: "octo/private-credential-free",
        visibility: ProviderRepositoryVisibility::Private,
        authority_profile: JobAuthorityProfile::CredentialFree,
        checks_authority_id: 0x603,
        private_source_authority_id: Some(0x703),
    },
    MatrixCase {
        tenant: "matrix-private-standard",
        connection_id: 0x304,
        installation_id: 304,
        repository_id: 404,
        repository_owner_id: 504,
        repository: "octo/private-standard",
        visibility: ProviderRepositoryVisibility::Private,
        authority_profile: JobAuthorityProfile::Standard,
        checks_authority_id: 0x604,
        private_source_authority_id: Some(0x704),
    },
];

#[derive(Debug)]
struct MatrixSelectionTrace {
    inner: Arc<dyn LogicalWorkSelectionRepository>,
    activation_consumes: Mutex<BTreeMap<Uuid, Vec<u64>>>,
}

impl MatrixSelectionTrace {
    fn new(inner: Arc<dyn LogicalWorkSelectionRepository>) -> Self {
        Self {
            inner,
            activation_consumes: Mutex::new(BTreeMap::new()),
        }
    }

    fn activation_consumes(&self) -> BTreeMap<Uuid, Vec<u64>> {
        self.activation_consumes
            .lock()
            .expect("activation consume trace")
            .clone()
    }
}

#[async_trait]
impl LogicalWorkSelectionRepository for MatrixSelectionTrace {
    async fn claim_next_logical_job_orchestration(
        &self,
        request: ClaimNextLogicalJobOrchestration,
    ) -> Result<LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionStoreError> {
        self.inner
            .claim_next_logical_job_orchestration(request)
            .await
    }

    async fn claim_next_logical_instance_materialization(
        &self,
        request: ClaimNextLogicalInstanceMaterialization,
    ) -> Result<LogicalInstanceMaterializationSelectionOutcome, LogicalWorkSelectionStoreError>
    {
        self.inner
            .claim_next_logical_instance_materialization(request)
            .await
    }

    async fn consume_selected_logical_job_orchestration(
        &self,
        request: ConsumeSelectedLogicalJobOrchestration,
    ) -> Result<ConsumedSelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError> {
        let result = self
            .inner
            .consume_selected_logical_job_orchestration(request)
            .await;
        if let Ok(consumed) = &result
            && let ConsumedLogicalJobOrchestrationAuthority::Activation(authority) =
                consumed.authority()
        {
            self.activation_consumes
                .lock()
                .expect("activation consume trace")
                .entry(authority.claim().logical_job_id().as_uuid())
                .or_default()
                .push(authority.claim().generation().get());
        }
        result
    }

    async fn consume_selected_logical_instance_materialization(
        &self,
        request: ConsumeSelectedLogicalInstanceMaterialization,
    ) -> Result<ConsumedSelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError>
    {
        self.inner
            .consume_selected_logical_instance_materialization(request)
            .await
    }

    async fn quarantine_logical_job_orchestration(
        &self,
        request: QuarantineLogicalJobOrchestration,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
        self.inner
            .quarantine_logical_job_orchestration(request)
            .await
    }

    async fn quarantine_logical_instance_materialization(
        &self,
        request: QuarantineLogicalInstanceMaterialization,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
        self.inner
            .quarantine_logical_instance_materialization(request)
            .await
    }
}

#[derive(Clone, Copy, Debug)]
struct ActivationDeadlineTrace {
    logical_job_id: Uuid,
    before: Instant,
    after: Instant,
}

#[derive(Debug)]
struct MatrixExecutorTrace {
    inner: Arc<dyn AutonomousWorkflowPhaseExecutor>,
    activation_deadlines: Mutex<Vec<ActivationDeadlineTrace>>,
}

impl MatrixExecutorTrace {
    fn new(inner: Arc<dyn AutonomousWorkflowPhaseExecutor>) -> Self {
        Self {
            inner,
            activation_deadlines: Mutex::new(Vec::new()),
        }
    }

    fn activation_deadlines(&self) -> Vec<ActivationDeadlineTrace> {
        self.activation_deadlines
            .lock()
            .expect("activation deadline trace")
            .clone()
    }
}

impl AutonomousWorkflowPhaseExecutor for MatrixExecutorTrace {
    fn execute_preparation<'a>(
        &'a self,
        lease: &'a mut AutonomousPreparationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        self.inner.execute_preparation(lease, shutdown, deadline)
    }

    fn execute_activation<'a>(
        &'a self,
        lease: &'a mut AutonomousActivationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move {
            let logical_job_id = lease.authority().claim().logical_job_id().as_uuid();
            let before = deadline.instant();
            let result = self
                .inner
                .execute_activation(lease, shutdown, deadline.clone())
                .await;
            let after = deadline.instant();
            self.activation_deadlines
                .lock()
                .expect("activation deadline trace")
                .push(ActivationDeadlineTrace {
                    logical_job_id,
                    before,
                    after,
                });
            result
        })
    }

    fn execute_materialization<'a>(
        &'a self,
        lease: &'a mut AutonomousMaterializationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        self.inner
            .execute_materialization(lease, shutdown, deadline)
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

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn public_private_x_profile_matrix_preserves_historical_job_ir_and_source_authentication()
-> TestResult {
    run_with_database(|database| async move { execute_matrix(database).await }).await
}

#[allow(clippy::too_many_lines)] // Keeping the serialized four-row scenario linear makes its phase order auditable.
async fn execute_matrix(database: Arc<TestDatabase>) -> TestResult {
    eprintln!("matrix stage: initial-config");
    let store = database.shared_store();
    let blobs = Arc::new(MemoryBlobStore::default());
    let broker = fixture_broker()?;
    let initial_config = load_config("initial", 1, false)?;
    let initial_verifier = GithubWebhookVerifier::new(WEBHOOK_SECRET)?;
    let initial_plan =
        GithubProviderBootstrapPlan::new(&initial_config, &broker, &initial_verifier)?;
    assert_eq!(initial_plan.manifests().len(), MATRIX.len());
    assert_eq!(initial_plan.authorities().len(), 6);
    for policy in initial_plan.runner_policies() {
        blobs.put_if_absent(policy.clone()).await?;
    }
    let initial_manifests = initial_plan.manifests().to_vec();
    for case in MATRIX {
        let manifest = manifest_for_case(&initial_manifests, case);
        assert_eq!(manifest.repository_visibility(), case.visibility);
        assert_eq!(manifest.authority_profile(), case.authority_profile);
        assert_eq!(manifest.revision().get(), 1);
    }
    eprintln!("matrix stage: initial-bootstrap");
    let ready = initial_plan.bootstrap(store.as_ref(), wall_now()).await?;
    assert_eq!(ready.manifest_count(), MATRIX.len());
    assert_eq!(ready.authority_count(), 6);

    let delivery_clock = Arc::new(SystemDeliveryClock);
    let ingress = automata_ci_github_delivery::GithubDeliveryIngress::new(
        initial_verifier,
        GithubServerServiceRevision::new(11)?,
        initial_plan.into_connections(),
        blobs.clone(),
        GithubDeliveryRepositories::new(store.clone()),
        delivery_clock.clone(),
    )?;
    let mut accepted_deliveries = Vec::with_capacity(MATRIX.len());
    for case in MATRIX {
        eprintln!("matrix stage: ingress {}", case.repository);
        let body = push_body(case);
        let accepted = ingress
            .accept(
                &signed_headers(
                    WEBHOOK_SECRET,
                    &body,
                    &format!("matrix-{}", repository_name(case)),
                ),
                body,
            )
            .await?;
        let delivery_id = accepted.receipt().delivery_id();
        eprintln!("matrix stage: initial-evidence {}", case.repository);
        let tenant = TenantScope::from_authenticated_tenant_id(case.tenant)?;
        let evidence = store
            .load_manifest_pinned_github_delivery_evidence(&tenant, delivery_id)
            .await?;
        assert_eq!(evidence.manifest_revision().get(), 1);
        assert_eq!(evidence.repository_visibility(), case.visibility);
        assert_eq!(
            evidence.manifest().authority_profile(),
            case.authority_profile
        );
        assert_eq!(
            evidence.private_source_authority().is_some(),
            case.visibility == ProviderRepositoryVisibility::Private
        );
        accepted_deliveries.push((case, delivery_id));
    }
    drop(ingress);

    let source = Arc::new(MatrixRepositorySource::new());
    let credentials = Arc::new(MatrixSourceCredentials::default());
    let admission = WorkflowAdmissionService::with_system_ports(
        blobs.clone(),
        store.clone(),
        Arc::new(GithubWorkflowPlanVerifier::new()),
    );
    let processor = Arc::new(GithubDeliveryWorkflowAdmissionProcessor::new(admission));
    let delivery_service = GithubDeliveryService::new_with_private_source_credentials(
        blobs.clone(),
        source.clone(),
        processor,
        store.clone(),
        credentials.clone(),
        delivery_clock,
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(0x801))?,
        GithubDeliveryWorkerConfig::default(),
        GithubDeliveryServiceConfig::default(),
    )?;

    let mut processed = 0_usize;
    for index in 0..MATRIX.len() {
        eprintln!("matrix stage: delivery-admission {index}");
        let outcome = delivery_service.run_once(CancellationToken::new()).await?;
        assert!(matches!(
            outcome,
            GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
        ));
        processed += 1;
    }
    assert_eq!(processed, MATRIX.len());
    assert_eq!(
        delivery_service.run_once(CancellationToken::new()).await?,
        GithubDeliveryServiceOutcome::Idle
    );
    assert_source_authentication(&source.observations(), &credentials);

    eprintln!("matrix stage: rotated-config");
    let rotated_config = load_config("rotated", 2, true)?;
    let rotated_verifier = GithubWebhookVerifier::new(WEBHOOK_SECRET)?;
    let rotated_plan =
        GithubProviderBootstrapPlan::new(&rotated_config, &broker, &rotated_verifier)?;
    assert_eq!(rotated_plan.authorities().len(), 6);
    for case in MATRIX {
        for authority_id in
            std::iter::once(case.checks_authority_id).chain(case.private_source_authority_id)
        {
            assert!(rotated_plan.authorities().iter().any(|authority| {
                authority.authority_id().as_uuid() == Uuid::from_u128(authority_id + 0x1_000)
                    && authority.policy_revision().get() == 8
            }));
        }
    }
    for policy in rotated_plan.runner_policies() {
        blobs.put_if_absent(policy.clone()).await?;
    }
    eprintln!("matrix stage: rotated-bootstrap");
    if let Err(error) = rotated_plan.bootstrap(store.as_ref(), wall_now()).await {
        for case in MATRIX {
            let initial = manifest_for_case(&initial_manifests, case);
            let desired = manifest_for_case(rotated_plan.manifests(), case);
            match store
                .load_current_github_provider_manifest(initial.tenant(), initial.connection_id())
                .await
            {
                Ok(current) => eprintln!(
                    "matrix rotated-bootstrap failure state {}: initial={}, desired={}, revision={}, policy={}",
                    case.repository,
                    current.manifest() == initial,
                    current.manifest() == desired,
                    current.manifest().revision().get(),
                    current.manifest().policy_revision().get(),
                ),
                Err(load_error) => eprintln!(
                    "matrix rotated-bootstrap failure state {}: load error {load_error}",
                    case.repository,
                ),
            }
        }
        let rotated_authority_ids = rotated_plan
            .authorities()
            .iter()
            .map(|authority| authority.authority_id().as_uuid())
            .collect::<Vec<_>>();
        let durable_rotated_authorities: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM github_server_service_authorities WHERE id = ANY($1)",
        )
        .bind(&rotated_authority_ids)
        .fetch_one(database.pool())
        .await?;
        eprintln!(
            "matrix rotated-bootstrap failure state: durable rotated authorities={durable_rotated_authorities}"
        );
        return Err(error.into());
    }
    for case in MATRIX {
        let initial = manifest_for_case(&initial_manifests, case);
        let current = store
            .load_current_github_provider_manifest(initial.tenant(), initial.connection_id())
            .await?;
        assert_eq!(current.manifest().repository_visibility(), case.visibility);
        assert_eq!(
            current.manifest().authority_profile(),
            opposite_profile(case.authority_profile)
        );
        assert_eq!(current.manifest().policy_revision().get(), 8);
        assert_eq!(current.manifest().revision().get(), 2);
    }
    for (case, delivery_id) in accepted_deliveries {
        eprintln!("matrix stage: historical-evidence {}", case.repository);
        let tenant = TenantScope::from_authenticated_tenant_id(case.tenant)?;
        let evidence = store
            .load_manifest_pinned_github_delivery_evidence(&tenant, delivery_id)
            .await?;
        assert_eq!(evidence.manifest_revision().get(), 1);
        assert_eq!(
            evidence.manifest().authority_profile(),
            case.authority_profile
        );
    }

    let source_calls_before_execution = source.observations().len();
    let credential_calls_before_execution = credentials.observations().len();
    let release_calls_before_execution = credentials.release_count();
    let workflow_clock: Arc<dyn AdmissionClock> = Arc::new(SystemAdmissionClock);
    let selection_trace = Arc::new(MatrixSelectionTrace::new(store.clone()));
    let selections: Arc<dyn LogicalWorkSelectionRepository> = selection_trace.clone();
    let preparations: Arc<dyn LogicalActivationPreparationStore> = store.clone();
    let activations: Arc<dyn LogicalActivationRepository> = store.clone();
    let materializations: Arc<dyn LogicalMaterializationRepository> = store.clone();
    let executor_trace = Arc::new(MatrixExecutorTrace::new(Arc::new(
        GithubAutonomousWorkflowPhaseExecutor::new(
            blobs.clone(),
            preparations.clone(),
            activations.clone(),
            materializations.clone(),
            workflow_clock.clone(),
        ),
    )));
    let executor: Arc<dyn AutonomousWorkflowPhaseExecutor> = executor_trace.clone();
    let workflow_service = AutonomousWorkflowService::new(
        selections,
        preparations,
        activations,
        materializations,
        executor,
        workflow_clock,
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(0x802))?,
        LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(0x803))?,
    );
    let expected_phase_count = MATRIX.len() * 3;
    let mut phases = Vec::with_capacity(expected_phase_count);
    for index in 0..expected_phase_count {
        eprintln!("matrix stage: autonomous-phase {index}");
        let outcome = workflow_service.run_once(CancellationToken::new()).await?;
        let AutonomousWorkflowOutcome::Completed(phase) = outcome else {
            return Err(std::io::Error::other(format!(
                "matrix workflow stopped before completion: {outcome:?}"
            ))
            .into());
        };
        phases.push(phase);
    }
    assert_eq!(
        phases
            .iter()
            .filter(|phase| **phase == AutonomousWorkflowPhase::Preparation)
            .count(),
        MATRIX.len()
    );
    assert_eq!(
        phases
            .iter()
            .filter(|phase| **phase == AutonomousWorkflowPhase::Activation)
            .count(),
        MATRIX.len()
    );
    assert_eq!(
        phases
            .iter()
            .filter(|phase| **phase == AutonomousWorkflowPhase::Materialization)
            .count(),
        MATRIX.len()
    );
    assert_eq!(
        workflow_service.run_once(CancellationToken::new()).await?,
        AutonomousWorkflowOutcome::Idle
    );
    let activation_trace_jobs =
        assert_activation_execution_traces(&selection_trace, &executor_trace);
    assert_eq!(source.observations().len(), source_calls_before_execution);
    assert_eq!(
        credentials.observations().len(),
        credential_calls_before_execution
    );
    assert_eq!(credentials.release_count(), release_calls_before_execution);

    eprintln!("matrix stage: activation-renewal-lineage");
    assert_activation_renewal_lineage(database.pool(), &activation_trace_jobs).await?;
    eprintln!("matrix stage: durable-profile-and-job-ir");
    assert_durable_profiles_and_job_ir(database.pool(), &blobs).await
}

fn assert_activation_execution_traces(
    selections: &MatrixSelectionTrace,
    executor: &MatrixExecutorTrace,
) -> BTreeSet<Uuid> {
    let activation_consumes = selections.activation_consumes();
    assert_eq!(activation_consumes.len(), MATRIX.len());
    for generations in activation_consumes.values() {
        assert_eq!(
            generations.as_slice(),
            [1, 2, 2],
            "activation must consume gen 1, reconcile gen 2, then revalidate gen 2"
        );
    }

    let deadline_traces = executor.activation_deadlines();
    assert_eq!(deadline_traces.len(), MATRIX.len());
    let mut deadline_jobs = BTreeSet::new();
    for trace in deadline_traces {
        assert!(
            deadline_jobs.insert(trace.logical_job_id),
            "each logical job executes activation exactly once"
        );
        assert!(
            trace.after <= trace.before,
            "activation renewal must not extend the absolute phase deadline"
        );
    }
    assert_eq!(
        deadline_jobs,
        activation_consumes.keys().copied().collect::<BTreeSet<_>>()
    );
    deadline_jobs
}

fn assert_source_authentication(
    observations: &[SourceObservation],
    credentials: &MatrixSourceCredentials,
) {
    assert_eq!(observations.len(), MATRIX.len());
    for case in MATRIX {
        let observed = observations
            .iter()
            .find(|observation| observation.repository == case.repository)
            .expect("every matrix repository has one source observation");
        let private = case.visibility == ProviderRepositoryVisibility::Private;
        assert_eq!(observed.credential_present, private, "{}", case.repository);
        assert_eq!(observed.credential_matched, private, "{}", case.repository);
    }
    let credential_observations = credentials.observations();
    assert_eq!(credential_observations.len(), 2);
    for observation in credential_observations {
        let case = case_for_repository(&observation.repository);
        assert_eq!(case.visibility, ProviderRepositoryVisibility::Private);
        assert_eq!(
            observation.action,
            GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision
        );
        assert_eq!(
            observation.authority_id,
            Uuid::from_u128(
                case.private_source_authority_id
                    .expect("private matrix case has source authority")
            )
        );
        assert_eq!(observation.policy_revision, 7);
    }
    assert_eq!(credentials.release_count(), 2);
}

async fn assert_activation_renewal_lineage(
    pool: &PgPool,
    activation_trace_jobs: &BTreeSet<Uuid>,
) -> TestResult {
    let rows = sqlx::query(ACTIVATION_RENEWAL_LINEAGE_QUERY)
        .fetch_all(pool)
        .await?;
    assert_eq!(rows.len(), MATRIX.len());
    let mut seen = BTreeSet::new();
    let mut sql_jobs = BTreeSet::new();
    for row in &rows {
        let repository = format!(
            "{}/{}",
            row.try_get::<String, _>("owner")?,
            row.try_get::<String, _>("name")?
        );
        let case = case_for_repository(&repository);
        assert!(
            seen.insert(repository.clone()),
            "duplicate activation lineage for {repository}"
        );
        assert!(
            sql_jobs.insert(row.try_get::<Uuid, _>("logical_job_id")?),
            "duplicate activation SQL target for {repository}"
        );
        assert_activation_renewal_identity(row, &repository)?;
        assert_activation_renewal_generation_and_time(row, &repository)?;
        assert_activation_renewal_digest_and_policy(row, &repository)?;
        assert_eq!(case.repository, repository);
    }
    assert_eq!(seen.len(), MATRIX.len());
    assert_eq!(&sql_jobs, activation_trace_jobs);
    Ok(())
}

fn assert_activation_renewal_identity(row: &PgRow, repository: &str) -> TestResult {
    assert_eq!(
        row.try_get::<i64, _>("activation_selection_count")?,
        1,
        "{repository} must have exactly one exact activation selection"
    );
    assert_eq!(
        row.try_get::<i64, _>("activation_renewal_count")?,
        1,
        "{repository} must have exactly one activation renewal receipt"
    );
    assert_eq!(
        row.try_get::<i64, _>("later_activation_renewal_count")?,
        0,
        "{repository} must not have a generation-3 activation renewal receipt"
    );
    let selection_id = row.try_get::<Uuid, _>("selection_id")?;
    assert_eq!(
        row.try_get::<Uuid, _>("activation_origin_selection_id")?,
        selection_id,
        "{repository} current activation must retain its selected origin"
    );
    assert_eq!(
        row.try_get::<Uuid, _>("renewal_selection_id")?,
        selection_id,
        "{repository} renewal must retain the same selection origin"
    );
    let selection_owner = row.try_get::<Uuid, _>("selection_owner_id")?;
    assert_eq!(
        row.try_get::<Uuid, _>("renewal_owner_id")?,
        selection_owner,
        "{repository} renewal owner"
    );
    assert_eq!(
        row.try_get::<Uuid, _>("publication_owner_id")?,
        selection_owner,
        "{repository} publication owner"
    );
    assert_eq!(
        row.try_get::<String, _>("selection_outcome")?,
        "claimed",
        "{repository} selection outcome"
    );
    assert_eq!(
        row.try_get::<String, _>("selection_authority_kind")?,
        "activation",
        "{repository} selection kind"
    );
    Ok(())
}

fn assert_activation_renewal_generation_and_time(row: &PgRow, repository: &str) -> TestResult {
    let selection_generation = row.try_get::<i64, _>("selection_generation")?;
    let predecessor_generation = row.try_get::<i64, _>("predecessor_generation")?;
    let successor_generation = row.try_get::<i64, _>("successor_generation")?;
    assert_eq!(selection_generation, 1, "{repository} selected generation");
    assert_eq!(
        predecessor_generation, selection_generation,
        "{repository} renewal predecessor"
    );
    assert_eq!(successor_generation, 2, "{repository} renewed generation");
    assert_eq!(
        row.try_get::<i64, _>("current_activation_generation")?,
        successor_generation,
        "{repository} durable current activation generation"
    );
    assert_eq!(
        row.try_get::<i64, _>("publication_generation")?,
        successor_generation,
        "{repository} publication generation"
    );
    let selection_claimed_at = row.try_get::<i64, _>("selection_claimed_at_ms")?;
    let selection_expires_at = row.try_get::<i64, _>("selection_expires_at_ms")?;
    let predecessor_claimed_at = row.try_get::<i64, _>("predecessor_claimed_at_ms")?;
    let predecessor_expires_at = row.try_get::<i64, _>("predecessor_expires_at_ms")?;
    assert_eq!(
        predecessor_claimed_at, selection_claimed_at,
        "{repository} predecessor claim start"
    );
    assert_eq!(
        predecessor_expires_at, selection_expires_at,
        "{repository} predecessor claim expiry"
    );
    let predecessor_duration = predecessor_expires_at
        .checked_sub(predecessor_claimed_at)
        .expect("validated predecessor duration");
    let requested_duration = row.try_get::<i64, _>("requested_duration_ms")?;
    assert!(
        requested_duration > predecessor_duration,
        "{repository} renewal request must strictly extend the predecessor duration"
    );
    let successor_claimed_at = row.try_get::<i64, _>("successor_claimed_at_ms")?;
    let successor_expires_at = row.try_get::<i64, _>("successor_expires_at_ms")?;
    assert_eq!(
        row.try_get::<i64, _>("publication_claimed_at_ms")?,
        successor_claimed_at,
        "{repository} publication claim start"
    );
    assert_eq!(
        row.try_get::<i64, _>("publication_expires_at_ms")?,
        successor_expires_at,
        "{repository} publication claim expiry"
    );
    assert_eq!(
        successor_expires_at.checked_sub(successor_claimed_at),
        Some(requested_duration),
        "{repository} successor duration"
    );
    assert!(
        successor_expires_at > selection_expires_at,
        "{repository} renewal must strictly extend durable authority"
    );
    let validated_at = row.try_get::<i64, _>("validated_at_ms")?;
    assert!(
        validated_at >= successor_claimed_at && validated_at < successor_expires_at,
        "{repository} renewal validation horizon"
    );
    Ok(())
}

fn assert_activation_renewal_digest_and_policy(row: &PgRow, repository: &str) -> TestResult {
    let selection_digest = row.try_get::<Vec<u8>, _>("selection_authority_digest")?;
    assert_eq!(
        row.try_get::<Vec<u8>, _>("renewal_authority_digest")?,
        selection_digest,
        "{repository} renewal authority digest"
    );
    assert_eq!(
        row.try_get::<Vec<u8>, _>("current_activation_input_digest")?,
        selection_digest,
        "{repository} durable activation input"
    );
    assert_eq!(
        row.try_get::<Vec<u8>, _>("publication_input_digest")?,
        selection_digest,
        "{repository} publication input"
    );
    let job_runtime_policy_revision = row.try_get::<i64, _>("job_runtime_policy_revision")?;
    assert_eq!(
        row.try_get::<i64, _>("renewal_runtime_policy_revision")?,
        job_runtime_policy_revision,
        "{repository} renewal runtime-policy revision"
    );
    assert_eq!(
        row.try_get::<i64, _>("publication_runtime_policy_revision")?,
        job_runtime_policy_revision,
        "{repository} publication runtime-policy revision"
    );
    let job_runtime_policy_digest = row.try_get::<Vec<u8>, _>("job_runtime_policy_digest")?;
    assert_eq!(
        row.try_get::<Vec<u8>, _>("renewal_runtime_policy_digest")?,
        job_runtime_policy_digest,
        "{repository} renewal runtime-policy digest"
    );
    assert_eq!(
        row.try_get::<Vec<u8>, _>("publication_runtime_policy_digest")?,
        job_runtime_policy_digest,
        "{repository} publication runtime-policy digest"
    );
    Ok(())
}

async fn assert_durable_profiles_and_job_ir(pool: &PgPool, blobs: &MemoryBlobStore) -> TestResult {
    let rows = sqlx::query(
        r"
        SELECT repository.owner, repository.name,
               job.authority_profile::text AS job_profile,
               claim.authority_profile::text AS claim_profile,
               preparation.authority_profile::text AS preparation_profile,
               publication.authority_profile::text AS publication_profile,
               materialization.authority_profile::text AS materialization_profile,
               concrete.authority_profile::text AS concrete_profile,
               instance.job_ir_digest, instance.job_ir_object_key,
               instance.job_ir_size_bytes, instance.job_ir_media_type
        FROM logical_workflow_jobs AS job
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN logical_workflow_activation_preparation_claims AS claim
          ON claim.logical_job_id = job.id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.logical_job_id = job.id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.logical_job_id = job.id
        JOIN logical_workflow_instances AS instance
          ON instance.logical_job_id = job.id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.logical_job_id = job.id
         AND materialization.instance_id = instance.id
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.logical_job_id = job.id
         AND concrete.instance_id = instance.id
        ORDER BY repository.owner, repository.name
        ",
    )
    .fetch_all(pool)
    .await?;
    assert_eq!(rows.len(), MATRIX.len());
    for row in rows {
        let repository = format!(
            "{}/{}",
            row.try_get::<String, _>("owner")?,
            row.try_get::<String, _>("name")?
        );
        let case = case_for_repository(&repository);
        let expected_profile = profile_text(case.authority_profile);
        for column in [
            "job_profile",
            "claim_profile",
            "preparation_profile",
            "publication_profile",
            "materialization_profile",
            "concrete_profile",
        ] {
            assert_eq!(
                row.try_get::<String, _>(column)?,
                expected_profile,
                "{repository} {column}"
            );
        }
        let digest_bytes = row.try_get::<Vec<u8>, _>("job_ir_digest")?;
        let digest = digest_bytes.try_into().map_err(|_| {
            std::io::Error::other(format!("{repository} has a non-SHA-256 JobIR digest"))
        })?;
        let descriptor = BlobDescriptor::new(
            BlobKey::new(row.try_get::<String, _>("job_ir_object_key")?)?,
            automata_ci_core::Sha256Digest::from_bytes(digest),
            u64::try_from(row.try_get::<i64, _>("job_ir_size_bytes")?)?,
            MediaType::new(row.try_get::<String, _>("job_ir_media_type")?)?,
        );
        let encoded = blobs
            .get_verified(&descriptor, descriptor.size())
            .await?
            .into_bytes();
        let envelope =
            automata_ci_protocol_protobuf::decode_job_ir(&encoded, &ProtocolLimits::default())?;
        assert_eq!(
            envelope.job().authority_profile(),
            case.authority_profile,
            "{repository}"
        );
        match case.authority_profile {
            JobAuthorityProfile::CredentialFree => assert!(matches!(
                envelope.job().permission_request(),
                JobPermissionRequest::Mapping(grants) if grants.is_empty()
            )),
            JobAuthorityProfile::Standard => assert!(matches!(
                envelope.job().permission_request(),
                JobPermissionRequest::Mapping(grants)
                    if grants.len() == 1
                        && grants[0].name() == "contents"
                        && grants[0].level() == PermissionLevel::Read
            )),
        }
    }
    Ok(())
}

fn manifest_for_case(
    manifests: &[GithubProviderManifest],
    case: MatrixCase,
) -> &GithubProviderManifest {
    manifests
        .iter()
        .find(|manifest| manifest.github_repository_name().as_str() == case.repository)
        .expect("matrix manifest")
}

fn case_for_repository(repository: &str) -> MatrixCase {
    MATRIX
        .into_iter()
        .find(|case| case.repository == repository)
        .expect("matrix repository")
}

fn repository_name(case: MatrixCase) -> &'static str {
    case.repository
        .split_once('/')
        .expect("matrix repository route")
        .1
}

fn opposite_profile(profile: JobAuthorityProfile) -> JobAuthorityProfile {
    match profile {
        JobAuthorityProfile::Standard => JobAuthorityProfile::CredentialFree,
        JobAuthorityProfile::CredentialFree => JobAuthorityProfile::Standard,
    }
}

fn profile_text(profile: JobAuthorityProfile) -> &'static str {
    match profile {
        JobAuthorityProfile::Standard => "standard",
        JobAuthorityProfile::CredentialFree => "credential_free",
    }
}

fn visibility_text(visibility: ProviderRepositoryVisibility) -> &'static str {
    match visibility {
        ProviderRepositoryVisibility::Public => "public",
        ProviderRepositoryVisibility::Private => "private",
    }
}

fn uuid(value: u128) -> String {
    Uuid::from_u128(value).to_string()
}

fn authority(id: u128, policy_revision: u64) -> Value {
    json!({
        "authority_id": uuid(id),
        "policy_revision": policy_revision
    })
}

fn repository_document(case: MatrixCase, manifest_revision: u64, rotated: bool) -> Value {
    let profile = if rotated {
        opposite_profile(case.authority_profile)
    } else {
        case.authority_profile
    };
    let policy_revision = if rotated { 8 } else { 7 };
    let authority_id_offset = if rotated { 0x1_000 } else { 0 };
    json!({
        "tenant_id": case.tenant,
        "connection_id": uuid(case.connection_id),
        "installation_id": case.installation_id,
        "repository_id": case.repository_id,
        "repository_owner_id": case.repository_owner_id,
        "repository": case.repository,
        "default_branch": "main",
        "visibility": visibility_text(case.visibility),
        "manifest_revision": manifest_revision,
        "policy_revision": policy_revision,
        "runtime_policy_revision": 1,
        "authority_profile": profile_text(profile),
        "runner_policy": serde_json::from_slice::<Value>(RUNNER_POLICY_CONFIGURATION)
            .expect("runner policy fixture"),
        "check_name": "Automata CI",
        "authorities": {
            "checks_write": authority(
                case.checks_authority_id + authority_id_offset,
                policy_revision,
            ),
            "private_repository_source_read": case.private_source_authority_id
                .map_or(Value::Null, |id| {
                    authority(id + authority_id_offset, policy_revision)
                })
        }
    })
}

fn config_document(manifest_revision: u64, rotated: bool) -> Value {
    json!({
        "schema": 2,
        "transport": {"mode": "github_dot_com"},
        "dashboard_url": "https://ci.automata.example/",
        "app": {
            "id": 42,
            "client_id": "Iv1.automata-provider",
            "jwt_issuer": "app_client_id",
            "private_key_source": "env:AUTOMATA_MATRIX_APP_KEY",
            "configuration_revision": 5
        },
        "webhook": {
            "hmac_secret_source": "env:AUTOMATA_MATRIX_WEBHOOK_KEY",
            "verifier_revision": 11
        },
        "repositories": MATRIX
            .into_iter()
            .map(|case| repository_document(case, manifest_revision, rotated))
            .collect::<Vec<_>>()
    })
}

fn load_config(
    name: &str,
    manifest_revision: u64,
    rotated: bool,
) -> TestResult<GithubProviderConfig> {
    let path = test_file(name);
    write_private_file(
        &path,
        serde_json::to_vec(&config_document(manifest_revision, rotated))?,
    )?;
    Ok(GithubProviderConfig::load(&SecretSource::File(path))?)
}

fn test_file(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("github-provider-end-to-end-matrix")
        .join(format!("{name}-{}.json", std::process::id()))
}

fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) -> TestResult {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn fixture_broker() -> TestResult<GithubAppCredentialBroker> {
    const PKCS8_DER: &[u8] = include_bytes!(
        "../../automata-ci-credential-github/tests/fixtures/rsa2048-test-key.pkcs8.der"
    );
    let pem = pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, PKCS8_DER)?;
    let private_key = SecretString::new(pem)?;
    let config = GithubAppCredentialConfig::github_dot_com(
        GithubAppIssuer::new("Iv1.automata-provider")?,
        GithubInstallationId::new(MATRIX[0].installation_id)?,
        "automata-ci-provider-matrix/0.1.0",
    )?;
    Ok(GithubAppCredentialBroker::new(config, &private_key)?)
}

#[derive(Debug)]
struct SystemDeliveryClock;

impl GithubDeliveryClock for SystemDeliveryClock {
    fn now(&self) -> UnixMillis {
        wall_now()
    }
}

fn wall_now() -> UnixMillis {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    UnixMillis::new(i64::try_from(milliseconds).unwrap_or(i64::MAX))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceObservation {
    repository: String,
    credential_present: bool,
    credential_matched: bool,
}

#[derive(Debug)]
struct MatrixRepositorySource {
    provider: ScmProviderId,
    sources: BTreeMap<String, RepositorySource>,
    observations: Mutex<Vec<SourceObservation>>,
}

impl MatrixRepositorySource {
    fn new() -> Self {
        let provider = ScmProviderId::new("github").expect("GitHub provider ID");
        let mut sources = BTreeMap::new();
        for case in MATRIX {
            let workflow = match case.authority_profile {
                JobAuthorityProfile::Standard => STANDARD_WORKFLOW,
                JobAuthorityProfile::CredentialFree => CREDENTIAL_FREE_WORKFLOW,
            };
            let source = RepositorySource::from_bytes(
                provider.clone(),
                ScmRepositoryId::new(case.repository).expect("matrix source repository"),
                ExactRevision::new(AFTER_COMMIT).expect("matrix source revision"),
                ArchiveFormat::TarGzip,
                archive(BTreeMap::from([(WORKFLOW_PATH, workflow.to_vec())])),
            );
            assert!(sources.insert(case.repository.to_owned(), source).is_none());
        }
        Self {
            provider,
            sources,
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<SourceObservation> {
        self.observations
            .lock()
            .expect("source observations lock")
            .clone()
    }
}

#[async_trait]
impl RepositorySourcePort for MatrixRepositorySource {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_repository_source(
        &self,
        request: RepositorySourceRequest<'_>,
    ) -> Result<RepositorySource, ScmError> {
        let repository = request.repository().as_str();
        let source = self
            .sources
            .get(repository)
            .expect("configured matrix repository");
        assert_eq!(request.revision(), source.revision());
        let credential_present = request.credential().is_some();
        let credential_matched = request
            .credential()
            .is_some_and(|credential| credential.expose_secret() == SOURCE_TOKEN);
        self.observations
            .lock()
            .expect("source observations lock")
            .push(SourceObservation {
                repository: repository.to_owned(),
                credential_present,
                credential_matched,
            });
        Ok(source.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CredentialObservation {
    repository: String,
    action: GithubDeliveryPrivateRepositoryAction,
    authority_id: Uuid,
    policy_revision: u64,
}

#[derive(Debug, Default)]
struct MatrixSourceCredentials {
    observations: Mutex<Vec<CredentialObservation>>,
    releases: Arc<AtomicUsize>,
}

impl MatrixSourceCredentials {
    fn observations(&self) -> Vec<CredentialObservation> {
        self.observations
            .lock()
            .expect("credential observations lock")
            .clone()
    }

    fn release_count(&self) -> usize {
        self.releases.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl GithubDeliverySourceCredentialProvider for MatrixSourceCredentials {
    async fn acquire(
        &self,
        request: GithubDeliverySourceCredentialRequest<'_>,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        let repository = request.identity().repository_identity().to_owned();
        self.observations
            .lock()
            .expect("credential observations lock")
            .push(CredentialObservation {
                repository: repository.clone(),
                action: request.action(),
                authority_id: request.authority_selector().authority_id().as_uuid(),
                policy_revision: request.authority_selector().policy_revision().get(),
            });
        let consumer = request
            .consumer_claim()
            .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        let binding = GithubDeliverySourceCredentialBinding::new(
            request.identity().clone(),
            request.repository_owner_id(),
            ScmRepositoryId::new(repository)
                .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?,
            request.authority_selector().clone(),
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())
                .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?,
            consumer,
            request.required_through(),
        )
        .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        let conservative_expires_at = UnixMillis::new(
            request
                .required_through()
                .get()
                .checked_add(1)
                .ok_or(GithubDeliverySourceCredentialProviderError::InvariantViolation)?,
        );
        GithubDeliverySourceCredential::new(
            binding,
            request.observed_at(),
            SecretString::new(SOURCE_TOKEN)
                .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?,
            conservative_expires_at,
            Box::new(ReleaseCounter {
                releases: self.releases.clone(),
            }),
        )
        .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)
    }
}

#[derive(Debug)]
struct ReleaseCounter {
    releases: Arc<AtomicUsize>,
}

#[async_trait]
impl GithubServerServiceCredentialRelease for ReleaseCounter {
    async fn release(self: Box<Self>) {
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

fn push_body(case: MatrixCase) -> Bytes {
    let (owner, name) = case
        .repository
        .split_once('/')
        .expect("matrix repository route");
    let private = case.visibility == ProviderRepositoryVisibility::Private;
    Bytes::from(format!(
        r#"{{"ref":"refs/heads/main","before":"{BEFORE_COMMIT}","after":"{AFTER_COMMIT}","created":false,"deleted":false,"forced":false,"repository":{{"id":{},"private":{private},"visibility":"{}","name":"{name}","full_name":"{}","owner":{{"id":{},"login":"{owner}"}}}},"installation":{{"id":{}}},"commits":[]}}"#,
        case.repository_id,
        visibility_text(case.visibility),
        case.repository,
        case.repository_owner_id,
        case.installation_id,
    ))
}

fn signed_headers(secret: &[u8], body: &[u8], delivery_id: &str) -> HeaderMap {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, body);
    let mut signature = String::from("sha256=");
    for byte in tag.as_ref() {
        write!(&mut signature, "{byte:02x}").expect("write to string");
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        X_HUB_SIGNATURE_256,
        HeaderValue::from_str(&signature).expect("signature header"),
    );
    headers.insert(X_GITHUB_EVENT, HeaderValue::from_static("push"));
    headers.insert(
        X_GITHUB_DELIVERY,
        HeaderValue::from_str(delivery_id).expect("delivery header"),
    );
    headers
}

fn archive(files: BTreeMap<&str, Vec<u8>>) -> Bytes {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    append_archive_entry(&mut builder, "repository-root", EntryType::Directory, &[]);
    for (path, bytes) in files {
        append_archive_entry(
            &mut builder,
            &format!("repository-root/{path}"),
            EntryType::Regular,
            &bytes,
        );
    }
    let encoder = builder.into_inner().expect("finish tar");
    Bytes::from(encoder.finish().expect("finish gzip"))
}

fn append_archive_entry(
    builder: &mut Builder<GzEncoder<Vec<u8>>>,
    path: &str,
    entry_type: EntryType,
    bytes: &[u8],
) {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(if entry_type.is_dir() { 0o755 } else { 0o644 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(u64::try_from(bytes.len()).expect("archive entry size"));
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .expect("append archive entry");
}
