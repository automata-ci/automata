#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use automata_ci_auth::{
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_core::{
    Architecture, AttemptId, ContextValue, FencingToken, JobAuthorityProfile, JobContentReference,
    JobExecutionContext, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobIrVersion,
    JobRuntimeContext, JobSource, Lease, LeaseId, OperatingSystem, OperationId, RunId,
    RunValueTemplates, RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SecretBinding, SemanticStep, Sha256Digest, ShellTemplate,
    StepId, StepIr, StrategyContext, UnixMillis, ValueTemplate, WorkflowJobKey,
};
use automata_ci_key_management::{
    EnvelopeCodec, KeyEncryptionContext, KeyEncryptionProvider, KeyId, KeyPurpose,
    LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AcknowledgeManagedSecretDelivery,
    ActivatedLogicalInstanceDescriptor, AdmissionObject, AdmissionRepository,
    AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob, AuthenticatedGithubDeliveryClaim,
    BindLogicalActivationPreparation, BuiltinRepositorySecretVersion, CancellationActor,
    CancellationReason, CancellationRepository as _, ClaimNextLogicalInstanceMaterialization,
    ClaimNextLogicalJobOrchestration, ClaimProviderDelivery, ClaimedLogicalInstanceMaterialization,
    ClaimedLogicalJobActivation, CommitLogicalInstanceMaterialization,
    ConfirmRepositorySecretVersionMutation, ConfirmRepositorySecretVersionMutationOutcome,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, EnsureGithubServerServiceAuthority,
    EnvironmentReviewDecision, GithubCheckHeadSha, GithubCheckName, GithubProviderManifest,
    GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    IssueLeasedJobSecretGrants, JobCredentialRequirements, JobEnvironmentActivationEvidence,
    JobEnvironmentGatePhase, JobEnvironmentGateState, JobEnvironmentRequirement, JobEventTrust,
    JobSourceKind, LogicalActivationObject, LogicalActivationPreparationStore as _,
    LogicalActivationPreparationTarget, LogicalActivationRepository as _,
    LogicalActivationWorkerId, LogicalInstanceMaterializationSelectionOutcome,
    LogicalInstanceMaterializationTarget, LogicalJobOrchestrationSelectionOutcome,
    LogicalMaterializationRepository as _, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    LogicalWorkSelectionRepository as _, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind,
    ManagedSecretAuthorityRepository as _, ManagedSecretAuthorityStoreError, ManagedSecretBinding,
    ManagedSecretBindingSet, ManagedSecretDeliveryMachine, ManagedSecretDeliveryOperationId,
    ManagedSecretDeliveryProposal, ObjectKey, OpenRunnerSession, PostgresSecretCustodyRepository,
    PostgresSecretManagementRepository, PrepareJobEnvironment, ProtectedEnvironmentRepository as _,
    ProtectedEnvironmentStoreError, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, PublishLogicalJobActivation, RepositoryId, RepositorySecretId,
    RepositorySecretManagementRepository as _, RepositorySecretMutationId, RepositorySecretName,
    RepositorySecretProviderMutationResult, RepositorySecretVersionId, RequestCancellation,
    ReserveRepositorySecretVersionMutation, ReserveRepositorySecretVersionMutationOutcome,
    ResolveManagedSecretAuthority, ReusableSecretPermission, ReviewJobEnvironment, RoutingDocument,
    RunnerGeneration, RunnerProtocolVersion, RunnerSessionFence, RunnerSessionRepository as _,
    SecretCustodyKeySet, SecretCustodyRepository as _, SecretWorkloadGrantId, StableRunnerSlot,
    TenantScope, VerifySecretCustody, VerifySecretCustodyOutcome, WorkflowAdmissionIdempotency,
    WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

const BUILTIN_VALUE_PURPOSE: &str = "secrets/builtin-value:v1";

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)] // Exact durable identities are clearer with their schema names.
struct BindingIdentity {
    grant_id: Uuid,
    secret_id: Uuid,
    mutation_id: Uuid,
    version_id: Uuid,
}

impl BindingIdentity {
    fn fresh() -> Self {
        Self {
            grant_id: Uuid::new_v4(),
            secret_id: Uuid::new_v4(),
            mutation_id: Uuid::new_v4(),
            version_id: Uuid::new_v4(),
        }
    }
}

struct LogicalFixture {
    tenant: String,
    delivery_key: String,
    manifest: GithubProviderManifest,
    repository_id: RepositoryId,
    command: AdmitLogicalWorkflowRun,
    logical_job_id: LogicalWorkflowJobId,
    bindings: Vec<BindingIdentity>,
    activation_environment: Option<automata_ci_store::DeploymentEnvironmentName>,
}

struct PreparedInstance {
    activated: ActivatedLogicalInstanceDescriptor,
    envelope: JobIrEnvelope,
    encoded: Vec<u8>,
    runtime_context: JobRuntimeContext,
    runtime_encoded: Vec<u8>,
}

struct QueuedExecutionFixture {
    tenant: String,
    repository_id: RepositoryId,
    run_id: RunId,
    job_id: JobId,
    attempt_id: AttemptId,
    runtime_context: JobRuntimeContext,
    runtime_context_digest: Sha256Digest,
    bindings: Vec<BindingIdentity>,
}

struct ExecutionFixture {
    tenant: String,
    repository_id: RepositoryId,
    run_id: RunId,
    job_id: JobId,
    lease: Lease,
    session: RunnerSessionFence,
    machine: ManagedSecretDeliveryMachine,
    runtime_context: JobRuntimeContext,
    runtime_context_digest: Sha256Digest,
    bindings: Vec<BindingIdentity>,
}

impl ExecutionFixture {
    fn time(&self, legacy_ms: i64) -> i64 {
        self.lease.issued_at().get() + (legacy_ms - 120_000)
    }

    fn request(
        &self,
        bindings: ManagedSecretBindingSet,
        observed_at: i64,
    ) -> Result<ResolveManagedSecretAuthority, automata_ci_store::ManagedSecretAuthorityValueError>
    {
        ResolveManagedSecretAuthority::new(
            TenantScope::from_authenticated_tenant_id(&self.tenant)
                .expect("fixture tenant is canonical"),
            self.repository_id,
            self.run_id,
            self.job_id,
            self.lease.clone(),
            self.session,
            StableRunnerSlot::new(1).expect("fixture slot"),
            self.runtime_context_digest,
            bindings,
            UnixMillis::new(self.time(observed_at)),
        )
    }

    fn exact_bindings(&self) -> ManagedSecretBindingSet {
        ManagedSecretBindingSet::from_runtime_context(&self.runtime_context)
            .expect("fixture runtime context has exact bindings")
    }

    fn delivery_request(
        &self,
        observed_at: i64,
        operation_id: Uuid,
        verifier: Sha256Digest,
    ) -> Result<ResolveManagedSecretAuthority, automata_ci_store::ManagedSecretAuthorityValueError>
    {
        Ok(self
            .request(self.exact_bindings(), observed_at)?
            .with_delivery(ManagedSecretDeliveryProposal::new(
                ManagedSecretDeliveryOperationId::from_uuid(operation_id)?,
                "delivery-test-key",
                verifier,
            )?))
    }

    fn authenticated_delivery_request(
        &self,
        observed_at: i64,
        operation_id: Uuid,
        verifier: Sha256Digest,
    ) -> Result<ResolveManagedSecretAuthority, automata_ci_store::ManagedSecretAuthorityValueError>
    {
        Ok(self
            .delivery_request(observed_at, operation_id, verifier)?
            .with_authenticated_machine(self.machine.clone()))
    }
}

struct SecretActor {
    tenant: String,
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: u64,
    time_origin_ms: i64,
}

impl SecretActor {
    fn time(&self, legacy_ms: i64) -> i64 {
        self.time_origin_ms + (legacy_ms - 120_000)
    }

    fn actor(&self) -> ManagementActor {
        ManagementActor::new(
            TenantId::new(&self.tenant).expect("tenant"),
            PrincipalId::new(self.principal_id.hyphenated().to_string()).expect("principal"),
            SessionId::new(self.session_id.hyphenated().to_string()).expect("session"),
            ManagementRevision::new(self.authorization_revision).expect("revision"),
            None,
            UnixTimestamp::from_seconds(
                u64::try_from(self.time_origin_ms / 1_000).expect("current fixture time"),
            ),
        )
    }
}

fn admission_object(key: String, byte: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        digest(byte),
        ObjectKey::new(key).expect("test object key"),
        512,
        media_type,
    )
    .expect("test admission object")
}

fn fixture_manifest(tenant: TenantScope) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    GithubProviderManifest::new(
        tenant,
        ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("provider connection"),
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryId::new(202).expect("repository"),
        GithubRepositoryName::new("example/project").expect("repository name"),
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(303).expect("app ID"),
        GithubServerServiceAppClientId::new("Iv1.managed-secret").expect("app client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        digest(0x71),
        GithubServerServiceRevision::new(1).expect("configuration revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(digest(0x72))
            .expect("webhook fingerprint"),
        GithubServerServiceRevision::new(1).expect("webhook revision"),
        GithubServerServiceRevision::new(1).expect("policy revision"),
        JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI").expect("check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1).expect("manifest revision"),
    )
}

fn logical_fixture_with_requirements(
    bindings: Vec<BindingIdentity>,
    credential_requirements: JobCredentialRequirements,
) -> LogicalFixture {
    let activation_environment = match credential_requirements.environment() {
        JobEnvironmentRequirement::None => None,
        JobEnvironmentRequirement::Environment(_) => Some(
            automata_ci_store::DeploymentEnvironmentName::new("production")
                .expect("test environment"),
        ),
    };
    let tenant = format!("secret-authority-{}", Uuid::new_v4().simple());
    let tenant_scope = TenantScope::from_authenticated_tenant_id(&tenant).expect("test tenant");
    let manifest = fixture_manifest(tenant_scope.clone());
    let repository_id = manifest.repository_id();
    let delivery_key = format!("secret-authority-{}", Uuid::new_v4());
    let workflow_id = automata_ci_core::WorkflowId::new();
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::new_v4());
    let run_id = RunId::new();
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::new_v4()).expect("test invocation");
    let logical_job_id = LogicalWorkflowJobId::from_uuid(Uuid::new_v4()).expect("test logical job");
    let logical_job = AdmittedLogicalWorkflowJob::new(
        logical_job_id,
        WorkflowJobKey::new("managed-secret").expect("test logical key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("test logical job")
    .with_credential_requirements(credential_requirements);
    let command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(delivery_key.clone())
            .expect("test idempotency"),
        digest(0x40),
        AdmissionRepository::new(
            repository_id,
            "github",
            manifest.github_repository_id().get().to_string(),
            "example",
            "project",
        )
        .expect("test repository"),
        workflow_id,
        ".ci/workflows/ci.yml",
        "Managed secret",
        "refs/heads/main",
        snapshot_id,
        admission_object("secret/source".to_owned(), 0x11, "application/yaml"),
        admission_object(
            "secret/plan".to_owned(),
            0x12,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object("secret/event".to_owned(), 0x13, "application/json"),
        vec![0x14; 20],
        vec![logical_job],
        UnixMillis::new(1_000),
    )
    .base_context(admission_object(
        "secret/base-context".to_owned(),
        0x15,
        "application/vnd.automata.job-runtime-context.protobuf",
    ))
    .build()
    .expect("test logical admission");
    LogicalFixture {
        tenant,
        delivery_key,
        manifest,
        repository_id,
        command,
        logical_job_id,
        bindings,
        activation_environment,
    }
}

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret authority test', 1, 1)",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn admit_authenticated_fixture(
    database: &TestDatabase,
    fixture: &LogicalFixture,
) -> TestResult {
    let manifest = &fixture.manifest;
    let configured_at = database_now_ms(database).await?;
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                UnixMillis::new(configured_at),
            ),
        )
        .await?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            GithubServerServiceAuthorityIdentity::new(
                manifest.tenant().clone(),
                GithubServerServiceAuthorityId::from_uuid(Uuid::new_v4())?,
                manifest.repository_id(),
                manifest.connection_id(),
                manifest.installation_id(),
                manifest.github_app_id(),
                manifest.github_repository_id(),
                manifest.github_repository_name().clone(),
                GithubServerServiceScope::ChecksWrite,
                manifest.app_client_id().clone(),
                manifest.jwt_issuer(),
                manifest.app_key_spki_sha256(),
                manifest.app_configuration_revision(),
                manifest.policy_revision(),
                digest(0x73),
            )?,
            UnixMillis::new(configured_at),
        )?)
        .await?;
    let delivery_observed_at = database_now_ms(database).await?;
    let accepted = database
        .store()
        .accept_manifest_pinned_github_delivery(AcceptManifestPinnedGithubDelivery::new(
            AcceptProviderDelivery::new(
                ProviderDeliveryIdentity::new(
                    manifest.tenant().clone(),
                    "github",
                    manifest.connection_id(),
                    manifest.installation_id(),
                    ProviderRepositoryCoordinates::new(
                        manifest.github_repository_id(),
                        manifest.repository_visibility(),
                        manifest.github_repository_name().as_str(),
                    )?,
                    fixture.delivery_key.clone(),
                )?,
                fixture.command.request_digest(),
                fixture.command.event().clone(),
                UnixMillis::new(delivery_observed_at),
            )?,
            ProviderRepositoryOwnerId::new(404)?,
            ProviderRepositoryOwnerId::new(404)?,
            GithubCheckHeadSha::new([0x14; 20])?,
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
        )?)
        .await?;
    let claim_observed_at = database_now_ms(database).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(claim_observed_at),
            UnixMillis::new(claim_observed_at + 60_000),
        )?)
        .await?
        .ok_or("accepted GitHub delivery was not claimable")?;
    assert_eq!(claimed.claim().delivery_id(), accepted.delivery_id());
    let command = logical_command_at(&fixture.command, claimed.claimed_at())?;
    let authenticated = AuthenticatedGithubDeliveryClaim::new(
        claimed.claim(),
        claimed.attempt(),
        claimed.claimed_at(),
        claimed.expires_at(),
    )?;
    database
        .store()
        .admit_authenticated_github_delivery(command.clone(), authenticated, command.admitted_at())
        .await?;
    Ok(())
}

fn logical_command_at(
    command: &AdmitLogicalWorkflowRun,
    admitted_at: UnixMillis,
) -> TestResult<AdmitLogicalWorkflowRun> {
    let mut builder = AdmitLogicalWorkflowRun::builder(
        command.tenant().clone(),
        command.idempotency().clone(),
        command.request_digest(),
        command.repository().clone(),
        command.workflow_id(),
        command.workflow_path(),
        command.workflow_name(),
        command.git_ref(),
        command.snapshot_id(),
        command.source().clone(),
        command.plan().clone(),
        command.run_id(),
        command.run_attempt(),
        command.root_invocation_id(),
        command.event_name(),
        command.event().clone(),
        command.head_sha().to_vec(),
        command.jobs().to_vec(),
        admitted_at,
    );
    if let Some(base_context) = command.base_context() {
        builder = builder.base_context(base_context.clone());
    }
    Ok(builder.build()?)
}

async fn claim_activation(
    database: &TestDatabase,
    fixture: &LogicalFixture,
) -> TestResult<ClaimedLogicalJobActivation> {
    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
    )?;
    let preparation = match select_orchestration(database, &target).await? {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            return Err(format!("expected preparation authority, got {authority:?}").into());
        }
    };
    let bound_at = database_now_ms(database).await?;
    let prepared = database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            preparation.descriptor().clone(),
            preparation.claim().clone(),
            preparation.descriptor().base_context().clone(),
            admission_object(
                "secret/needs-context".to_owned(),
                0x52,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            UnixMillis::new(bound_at),
        )?)
        .await?;
    match select_orchestration(database, &target).await? {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
            assert_eq!(claimed.claim().input_digest(), prepared.input_digest());
            Ok(claimed)
        }
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            Err(format!("expected activation authority, got {authority:?}").into())
        }
    }
}

async fn select_orchestration(
    database: &TestDatabase,
    expected_target: &LogicalActivationPreparationTarget,
) -> TestResult<ConsumedLogicalJobOrchestrationAuthority> {
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
            LogicalActivationWorkerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(observed_at),
            60_000,
        )?)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected orchestration selection, got {outcome:?}").into()),
    };
    assert_eq!(selected.target(), expected_target);
    Ok(database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?
        .authority()
        .clone())
}

async fn select_materialization(
    database: &TestDatabase,
    expected_target: LogicalInstanceMaterializationTarget,
) -> TestResult<ClaimedLogicalInstanceMaterialization> {
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_instance_materialization(ClaimNextLogicalInstanceMaterialization::new(
            LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
            LogicalMaterializationWorkerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(observed_at),
            60_000,
        )?)
        .await?
    {
        LogicalInstanceMaterializationSelectionOutcome::Selected(selected) => selected,
        outcome => {
            return Err(format!("expected materialization selection, got {outcome:?}").into());
        }
    };
    assert_eq!(selected.target(), &expected_target);
    Ok(database
        .store()
        .consume_selected_logical_instance_materialization(
            ConsumeSelectedLogicalInstanceMaterialization::new(selected),
        )
        .await?
        .authority()
        .clone())
}

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    pool_now_ms(database.pool()).await
}

async fn pool_now_ms(pool: &PgPool) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(pool)
            .await?,
    )
}

fn concrete_job_id(
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    matrix_digest: Sha256Digest,
) -> JobId {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.workflow-service.logical-job-id.v1\0");
    hasher.update(run_id.as_uuid().as_bytes());
    hasher.update(invocation_id.as_uuid().as_bytes());
    hasher.update(logical_job_id.as_uuid().as_bytes());
    hasher.update(0_u32.to_be_bytes());
    hasher.update(1_u32.to_be_bytes());
    hasher.update(matrix_digest.as_bytes());
    let output: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&output[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    JobId::from_uuid(Uuid::from_bytes(bytes))
}

fn content_reference(object: &AdmissionObject) -> JobContentReference {
    JobContentReference::new(
        object.object_key().as_str(),
        object.digest(),
        object.encoded_size(),
        object.media_type(),
    )
}

fn activation_reference(object: &LogicalActivationObject) -> JobContentReference {
    JobContentReference::new(
        object.object_key().as_str(),
        object.digest(),
        object.encoded_size(),
        object.media_type(),
    )
}

#[allow(clippy::too_many_lines)] // Current WorkflowPlan-v2 fixture retains every exact descriptor.
fn prepare_instance(
    fixture: &LogicalFixture,
    claimed: &ClaimedLogicalJobActivation,
) -> PreparedInstance {
    let matrix_digest = digest(0x61);
    let identity = JobInstanceIdentity::new("managed-secret", 0, 1, matrix_digest)
        .expect("test matrix identity");
    let empty = ContextValue::object(BTreeMap::new()).expect("test empty context");
    let secrets = fixture
        .bindings
        .iter()
        .enumerate()
        .map(|(index, binding)| {
            (
                format!("SECRET_{index}"),
                SecretBinding::new(binding.grant_id.hyphenated().to_string())
                    .and_then(|value| {
                        value.with_version_id(binding.version_id.hyphenated().to_string())
                    })
                    .expect("exact managed binding"),
            )
        })
        .collect();
    let runtime_context = JobRuntimeContext::new(
        empty.clone(),
        empty.clone(),
        empty,
        StrategyContext::new(false, 0, 1, 1).expect("test strategy"),
        BTreeMap::new(),
        secrets,
    )
    .expect("test runtime context");
    let runtime_encoded = serde_json::to_vec(&runtime_context).expect("encode runtime context");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes(Sha256::digest(&runtime_encoded).into()),
        ObjectKey::new(format!(
            "secret/{}/runtime-context",
            fixture.command.run_id().as_uuid()
        ))
        .expect("test runtime key"),
        u64::try_from(runtime_encoded.len()).expect("test runtime size"),
    )
    .expect("test runtime descriptor");
    let workspace = "/srv/work/secret";
    let step = StepIr::new_literal_name(
        StepId::new("run").expect("test step ID"),
        "Run",
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("true").expect("test command"),
            ShellTemplate::default_shell(),
        )),
    )
    .expect("test step");
    let job = JobIr::new(
        concrete_job_id(
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.logical_job_id,
            matrix_digest,
        ),
        fixture.command.run_id(),
        "Managed secret",
        RunnerRequirements::default(),
        identity.clone(),
        false,
        vec![step],
    );
    let execution = claimed.execution();
    let mut job_execution = JobExecutionContext::new(
        execution.workflow_name(),
        execution.git_ref(),
        workspace,
        content_reference(claimed.event()),
        activation_reference(&runtime),
    )
    .with_run_id_alias(execution.run_id_alias())
    .with_run_number(execution.run_number())
    .with_run_attempt(execution.run_attempt());
    if let Some(actor) = execution.actor() {
        job_execution = job_execution.with_actor(actor);
    }
    let envelope = JobIrEnvelope::new(
        execution.workflow_id(),
        JobSource::new(
            "github",
            "example/project",
            "0123456789abcdef",
            ".ci/workflows/ci.yml",
            "push",
        ),
        job_execution,
        job,
    );
    envelope.validate().expect("current test JobIR");
    let encoded = serde_json::to_vec(&envelope).expect("encode test JobIR");
    let activated = ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        workspace,
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new(format!(
                "secret/{}/job-ir",
                fixture.command.run_id().as_uuid()
            ))
            .expect("test JobIR key"),
            u64::try_from(encoded.len()).expect("test JobIR size"),
        )
        .expect("test JobIR descriptor"),
        runtime,
        JobEnvironmentActivationEvidence::new(
            fixture.activation_environment.clone(),
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        ),
    )
    .expect("test activated instance");
    PreparedInstance {
        activated,
        envelope,
        encoded,
        runtime_context,
        runtime_encoded,
    }
}

async fn seed_queued_execution(
    database: &TestDatabase,
    bindings: Vec<BindingIdentity>,
    credential_requirements: JobCredentialRequirements,
) -> TestResult<QueuedExecutionFixture> {
    let fixture = logical_fixture_with_requirements(bindings, credential_requirements);
    seed_tenant(database, &fixture.tenant).await?;
    admit_authenticated_fixture(database, &fixture).await?;
    let claimed = claim_activation(database, &fixture).await?;
    let prepared = prepare_instance(&fixture, &claimed);
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            claimed.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    let target = LogicalInstanceMaterializationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
        prepared.activated.id(),
    )?;
    let materialization = select_materialization(database, target).await?;
    let materialized = database
        .store()
        .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
            &materialization,
            &prepared.encoded,
            &prepared.envelope,
            &prepared.runtime_encoded,
            &prepared.runtime_context,
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;

    let runtime_context_digest =
        Sha256Digest::from_bytes(Sha256::digest(&prepared.runtime_encoded).into());
    Ok(QueuedExecutionFixture {
        tenant: fixture.tenant,
        repository_id: fixture.repository_id,
        run_id: fixture.command.run_id(),
        job_id: materialized.job_id(),
        attempt_id: materialized.attempt_id(),
        runtime_context: prepared.runtime_context,
        runtime_context_digest,
        bindings: fixture.bindings,
    })
}

#[allow(clippy::too_many_lines)]
async fn lease_execution(
    database: &TestDatabase,
    queued: QueuedExecutionFixture,
) -> TestResult<ExecutionFixture> {
    let runner_id = RunnerId::new();
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    );
    let external_identity = format!("secret-runner-identity-{}", runner_id.as_uuid().simple());
    let certificate_sha256 =
        Sha256Digest::from_bytes(Sha256::digest(runner_id.as_uuid().as_bytes()).into());
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots, status,
            desired_state, external_identity, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, $3, $3, $4::jsonb, 1, 'online', 'active', $5, 1, 1
        )
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(&queued.tenant)
    .bind(format!("secret-runner-{}", runner_id.as_uuid().simple()))
    .bind(serde_json::to_value(&capabilities)?)
    .bind(&external_identity)
    .execute(database.pool())
    .await?;
    let session = database
        .store()
        .open_session(OpenRunnerSession::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(1)?,
            RunnerProtocolVersion::new(5)?,
            JobIrVersion::current(),
            RoutingDocument::new(serde_json::to_string(&capabilities)?)?,
            UnixMillis::new(database_now_ms(database).await? - 10_000),
        ))
        .await?;
    let lease_id = LeaseId::new();
    let fence = FencingToken::new(7)?;
    let lease_issued_at = database_now_ms(database).await?;
    let lease_expires_at = lease_issued_at + 335_000;
    sqlx::query(
        r"
        INSERT INTO runner_machine_certificates (
            leaf_sha256, runner_id, expires_at_seconds, revoked_at_seconds
        ) VALUES ($1, $2, $3, NULL)
        ",
    )
    .bind(certificate_sha256.as_bytes().as_slice())
    .bind(runner_id.as_uuid())
    .bind(lease_expires_at / 1_000 + 600)
    .execute(database.pool())
    .await?;
    let changed = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'leased', fencing_token = $2, lease_id = $3,
            runner_id = $4, lease_issued_at_ms = $8,
            lease_expires_at_ms = $9, runner_session_id = $5,
            runner_session_epoch = $6, runner_generation = $7,
            runner_slot = 1, changed_at_ms = $8
        WHERE id = $1 AND lifecycle = 'queued'
        ",
    )
    .bind(queued.attempt_id.as_uuid())
    .bind(i64::try_from(fence.get())?)
    .bind(lease_id.as_uuid())
    .bind(runner_id.as_uuid())
    .bind(session.fence().session_id().as_uuid())
    .bind(i64::try_from(session.fence().session_epoch().get())?)
    .bind(i64::try_from(session.fence().runner_generation().get())?)
    .bind(lease_issued_at)
    .bind(lease_expires_at)
    .execute(database.pool())
    .await?;
    if changed.rows_affected() != 1 {
        return Err("initial attempt was not queued".into());
    }
    Ok(ExecutionFixture {
        tenant: queued.tenant,
        repository_id: queued.repository_id,
        run_id: queued.run_id,
        job_id: queued.job_id,
        lease: Lease::new(
            lease_id,
            queued.attempt_id,
            runner_id,
            fence,
            UnixMillis::new(lease_issued_at),
            UnixMillis::new(lease_expires_at),
        )?,
        session: session.fence(),
        machine: ManagedSecretDeliveryMachine::new(external_identity, certificate_sha256)?,
        runtime_context: queued.runtime_context,
        runtime_context_digest: queued.runtime_context_digest,
        bindings: queued.bindings,
    })
}

async fn seed_current_execution(
    database: &TestDatabase,
    bindings: Vec<BindingIdentity>,
) -> TestResult<ExecutionFixture> {
    let queued =
        seed_queued_execution(database, bindings, JobCredentialRequirements::default()).await?;
    lease_execution(database, queued).await
}

#[allow(clippy::too_many_lines)] // Human authority fixture spells out all durable evidence.
async fn seed_secret_actor(
    pool: &PgPool,
    tenant: &str,
    time_origin_ms: i64,
) -> TestResult<SecretActor> {
    let principal_id = Uuid::new_v4();
    let provider_subject = format!("secret-authority-{}", principal_id.simple());
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Secret authority actor', 1, 1)",
    )
    .bind(principal_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id, provider_id, provider_subject, provider_login,
            normalized_login, first_authenticated_at_ms, last_authenticated_at_ms,
            last_observed_at_ms, created_at_ms, updated_at_ms
        ) VALUES ($1, 'github', $2, $3, $3, 1, 1, 1, 1, 1)
        ",
    )
    .bind(principal_id)
    .bind(&provider_subject)
    .bind(format!("actor-{}", principal_id.simple()))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1, $2, 1, 1)",
    )
    .bind(tenant)
    .bind(principal_id)
    .execute(pool)
    .await?;
    let role_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id, id, name, display_name, role_kind, immutable,
            created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, 'Secret authority manager', 'custom', FALSE, $4, 1, 1)
        ",
    )
    .bind(tenant)
    .bind(role_id)
    .bind(format!("secret-authority-{}", role_id.simple()))
    .bind(principal_id)
    .execute(pool)
    .await?;
    for permission in [
        "secrets:create",
        "secrets:update",
        "environments:approve",
        "environments:manage",
    ] {
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name,
                granted_by_principal_id, granted_at_ms
            ) VALUES ($1, $2, $3, $4, 1)
            ",
        )
        .bind(tenant)
        .bind(role_id)
        .bind(permission)
        .bind(principal_id)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id, id, principal_id, role_id, scope_kind,
            assignment_source, created_by_principal_id, created_at_ms
        ) VALUES ($1, $2, $3, $4, 'tenant', 'manual', $3, 1)
        ",
    )
    .bind(tenant)
    .bind(Uuid::new_v4())
    .bind(principal_id)
    .bind(role_id)
    .execute(pool)
    .await?;
    let authorization_revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(tenant)
    .bind(principal_id)
    .fetch_one(pool)
    .await?;
    let session_id = Uuid::new_v4();
    let mut token_hash = [0_u8; 32];
    token_hash[..16].copy_from_slice(session_id.as_bytes());
    token_hash[16..].copy_from_slice(session_id.as_bytes());
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id, tenant_id, principal_id, provider_id, provider_subject,
            session_kind, audience, token_hash, token_hash_key_id,
            authorization_revision, issued_at_ms, last_seen_at_ms,
            idle_expires_at_ms, expires_at_ms
        ) VALUES (
            $1, $2, $3, 'github', $4, 'browser', 'automata.web',
            $5, 'secret-authority-session-v1', $6, $7, $7, $8, $9
        )
        ",
    )
    .bind(session_id)
    .bind(tenant)
    .bind(principal_id)
    .bind(&provider_subject)
    .bind(token_hash.as_slice())
    .bind(authorization_revision)
    .bind(time_origin_ms - 30_000)
    .bind(time_origin_ms + 620_000)
    .bind(time_origin_ms + 630_000)
    .execute(pool)
    .await?;
    Ok(SecretActor {
        tenant: tenant.to_owned(),
        principal_id,
        session_id,
        authorization_revision: u64::try_from(authorization_revision)?,
        time_origin_ms,
    })
}

async fn activate_builtin_provider(pool: &PgPool, tenant: &str, updated_at_ms: i64) -> TestResult {
    let result = sqlx::query(
        r"
        UPDATE secret_providers
        SET status = 'active', health = 'healthy', revision = 2, updated_at_ms = $2
        WHERE tenant_id = $1 AND provider_id = 'builtin'
          AND status = 'unconfigured' AND revision = 1
        ",
    )
    .bind(tenant)
    .bind(updated_at_ms)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err("built-in provider did not activate exactly once".into());
    }
    Ok(())
}

async fn seed_repository_secret(
    pool: &PgPool,
    repository_id: RepositoryId,
    actor: &SecretActor,
    binding: BindingIdentity,
    index: usize,
) -> TestResult {
    let repository = PostgresSecretManagementRepository::new(pool.clone());
    let secret_id = RepositorySecretId::from_uuid(binding.secret_id)?;
    let mutation_id = RepositorySecretMutationId::from_uuid(binding.mutation_id, secret_id)?;
    let request = ReserveRepositorySecretVersionMutation::create(
        actor.actor(),
        mutation_id,
        secret_id,
        repository_id,
        RepositorySecretName::new(format!("authority_token_{index}"))?,
        None,
    )?;
    let ReserveRepositorySecretVersionMutationOutcome::FreshReservation(reservation) = repository
        .reserve_repository_secret_version_mutation(request)
        .await?
    else {
        return Err("repository secret was not freshly reserved".into());
    };
    stage_encrypted_builtin_version(
        pool,
        actor,
        binding,
        reservation.provider_create_request_id(),
        format!("test-secret-value-{index}").as_bytes(),
    )
    .await?;
    let target = BuiltinRepositorySecretVersion::new(
        secret_id,
        RepositorySecretVersionId::from_uuid(binding.version_id)?,
        1,
    )?;
    let outcome = repository
        .confirm_repository_secret_version_mutation(ConfirmRepositorySecretVersionMutation::new(
            actor.actor(),
            mutation_id,
            RepositorySecretProviderMutationResult::BuiltinCreated(target),
        ))
        .await?;
    if !matches!(
        outcome,
        ConfirmRepositorySecretVersionMutationOutcome::Applied(_)
    ) {
        return Err("repository secret version was not applied".into());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn stage_encrypted_builtin_version(
    pool: &PgPool,
    actor: &SecretActor,
    binding: BindingIdentity,
    create_request_id: &str,
    plaintext: &[u8],
) -> TestResult {
    let key_id = KeyId::new("secret-authority-test-kek-v1")?;
    let key = LocalKeyMaterial::new(key_id.clone(), SecretBytes::new(vec![0x79; 32])?)?;
    let key_provider: Arc<dyn KeyEncryptionProvider> =
        Arc::new(LocalAes256GcmKeyring::new(key, Vec::new(), [])?);
    let custody = PostgresSecretCustodyRepository::new(pool.clone())
        .with_key_encryption_provider(Arc::clone(&key_provider));
    assert!(matches!(
        custody
            .verify_or_create_secret_custody(VerifySecretCustody::configured(
                SecretCustodyKeySet::new(key_id, Vec::new())?,
            ))
            .await?,
        VerifySecretCustodyOutcome::Verified(_)
    ));
    let codec = EnvelopeCodec::new(key_provider);
    let context = KeyEncryptionContext::new(
        &actor.tenant,
        KeyPurpose::new(BUILTIN_VALUE_PURPOSE)?,
        binding.version_id.hyphenated().to_string(),
    )?;
    let envelope = codec
        .seal(&context, SecretBytes::new(plaintext.to_vec())?)
        .await?;
    let (schema, wrapped, nonce, ciphertext) = envelope.into_parts();
    let (key_id, wrapped_data_key) = wrapped.into_parts();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO secret_versions (
            tenant_id, id, secret_id, version_number, provider_id,
            create_request_id, storage_kind, created_by_principal_id, created_at_ms
        ) VALUES ($1, $2, $3, 1, 'builtin', $4, 'built_in_ciphertext', $5, $6)
        ",
    )
    .bind(&actor.tenant)
    .bind(binding.version_id)
    .bind(binding.secret_id)
    .bind(create_request_id)
    .bind(actor.principal_id)
    .bind(actor.time(100_000))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_lifecycle (
            tenant_id, secret_version_id, secret_id, version_number,
            provider_id, mutation_id, status, revision,
            changed_by_principal_id, changed_at_ms
        ) VALUES ($1, $2, $3, 1, 'builtin', $4, 'staged', 1, $5, $6)
        ",
    )
    .bind(&actor.tenant)
    .bind(binding.version_id)
    .bind(binding.secret_id)
    .bind(binding.mutation_id)
    .bind(actor.principal_id)
    .bind(actor.time(100_000))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_envelopes (
            tenant_id, secret_version_id, secret_id, version_number,
            storage_kind, envelope_generation, ciphertext, nonce,
            wrapped_data_key, wrapping_key_id, envelope_schema, created_at_ms
        ) VALUES (
            $1, $2, $3, 1, 'built_in_ciphertext', 1, $4, $5, $6, $7, $8, $9
        )
        ",
    )
    .bind(&actor.tenant)
    .bind(binding.version_id)
    .bind(binding.secret_id)
    .bind(ciphertext)
    .bind(nonce.as_slice())
    .bind(wrapped_data_key)
    .bind(key_id.as_str())
    .bind(i32::from(schema))
    .bind(actor.time(100_000))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_envelope_heads (
            tenant_id, secret_version_id, envelope_generation, revision, updated_at_ms
        ) VALUES ($1, $2, 1, 1, $3)
        ",
    )
    .bind(&actor.tenant)
    .bind(binding.version_id)
    .bind(actor.time(100_000))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn seed_environment(
    pool: &PgPool,
    execution: &ExecutionFixture,
    actor: &SecretActor,
    protected: bool,
) -> TestResult<(Uuid, Option<Uuid>)> {
    let environment_id = Uuid::new_v4();
    let (mode, required) = if protected {
        ("required_approvals", 1_i16)
    } else {
        ("unprotected", 0_i16)
    };
    sqlx::query(
        r"
        INSERT INTO repository_environments (
            tenant_id, repository_id, id, name, normalized_name,
            protection_mode, required_approvals, prevent_self_review,
            created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8, $9, $9)
        ",
    )
    .bind(&execution.tenant)
    .bind(execution.repository_id.as_uuid())
    .bind(environment_id)
    .bind(format!("Environment {}", environment_id.simple()))
    .bind(format!("environment-{}", environment_id.simple()))
    .bind(mode)
    .bind(required)
    .bind(actor.principal_id)
    .bind(execution.time(110_000))
    .execute(pool)
    .await?;
    if !protected {
        return Ok((environment_id, None));
    }
    let approval_now = pool_now_ms(pool).await?;
    let current_authorization_revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(&execution.tenant)
    .bind(actor.principal_id)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO repository_environment_reviewers (
            tenant_id, repository_id, environment_id, environment_revision,
            principal_id, principal_authorization_revision,
            granted_by_principal_id, grantor_authorization_revision, granted_at_ms
        ) VALUES ($1, $2, $3, 1, $4, $5, $4, $5, $6)
        ",
    )
    .bind(&execution.tenant)
    .bind(execution.repository_id.as_uuid())
    .bind(environment_id)
    .bind(actor.principal_id)
    .bind(current_authorization_revision)
    .bind(approval_now)
    .execute(pool)
    .await?;
    let approval_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO protected_environment_approval_requests (
            tenant_id, repository_id, environment_id, run_id, job_id,
            attempt_id, id, required_approvals, prevent_self_review,
            requested_by_principal_id, status, created_at_ms, expires_at_ms,
            resolved_at_ms, resolution_reason, revision
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, 1, FALSE, $8,
            'pending', $9, $10, NULL, NULL, 1
        )
        ",
    )
    .bind(&execution.tenant)
    .bind(execution.repository_id.as_uuid())
    .bind(environment_id)
    .bind(execution.run_id.as_uuid())
    .bind(execution.job_id.as_uuid())
    .bind(execution.lease.attempt_id().as_uuid())
    .bind(approval_id)
    .bind(actor.principal_id)
    .bind(approval_now - 1)
    .bind(execution.time(300_000))
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO protected_environment_approval_decisions (
            tenant_id, request_id, principal_id, decision, reason, decided_at_ms
        ) VALUES ($1, $2, $3, 'approve', 'policy_reviewed', $4)
        ",
    )
    .bind(&execution.tenant)
    .bind(approval_id)
    .bind(actor.principal_id)
    .bind(approval_now)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        UPDATE protected_environment_approval_requests
        SET status = 'approved', resolved_at_ms = $3,
            resolution_reason = 'approval_threshold_met', revision = 2
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(&execution.tenant)
    .bind(approval_id)
    .bind(approval_now)
    .execute(pool)
    .await?;
    Ok((environment_id, Some(approval_id)))
}

async fn assign_environment_reviewer(
    pool: &PgPool,
    queued: &QueuedExecutionFixture,
    environment_id: Uuid,
    actor: &SecretActor,
) -> TestResult {
    let granted_at_ms = pool_now_ms(pool).await?;
    let authorization_revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(&queued.tenant)
    .bind(actor.principal_id)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO repository_environment_reviewers (
            tenant_id, repository_id, environment_id, environment_revision,
            principal_id, principal_authorization_revision,
            granted_by_principal_id, grantor_authorization_revision, granted_at_ms
        ) VALUES ($1, $2, $3, 1, $4, $5, $4, $5, $6)
        ",
    )
    .bind(&queued.tenant)
    .bind(queued.repository_id.as_uuid())
    .bind(environment_id)
    .bind(actor.principal_id)
    .bind(authorization_revision)
    .bind(granted_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

async fn prepare_protected_environment_gate(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
    actor: &SecretActor,
    approval_expires_at_ms: i64,
) -> TestResult<(Uuid, Uuid)> {
    prepare_protected_environment_gate_with_self_review(
        database,
        queued,
        actor,
        approval_expires_at_ms,
        false,
    )
    .await
}

async fn prepare_protected_environment_gate_with_self_review(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
    actor: &SecretActor,
    approval_expires_at_ms: i64,
    prevent_self_review: bool,
) -> TestResult<(Uuid, Uuid)> {
    let environment_id = Uuid::new_v4();
    let now = database_now_ms(database).await?;
    sqlx::query(
        r"
        INSERT INTO repository_environments (
            tenant_id, repository_id, id, name, normalized_name,
            protection_mode, required_approvals, prevent_self_review,
            created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, $3, 'Production', 'production',
            'required_approvals', 1, $4, $5, $6, $6
        )
        ",
    )
    .bind(&queued.tenant)
    .bind(queued.repository_id.as_uuid())
    .bind(environment_id)
    .bind(prevent_self_review)
    .bind(actor.principal_id)
    .bind(now)
    .execute(database.pool())
    .await?;
    assign_environment_reviewer(database.pool(), queued, environment_id, actor).await?;

    let approval_id = Uuid::new_v4();
    let tenant = TenantScope::from_authenticated_tenant_id(&queued.tenant)?;
    assert_eq!(
        database
            .store()
            .prepare_job_environment(PrepareJobEnvironment::new(
                tenant,
                queued.attempt_id,
                Some(automata_ci_store::DeploymentEnvironmentName::new(
                    "production",
                )?),
                queued.runtime_context_digest,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
                approval_id,
                UnixMillis::new(now),
                UnixMillis::new(approval_expires_at_ms),
            )?)
            .await?,
        JobEnvironmentGateState::Waiting
    );
    Ok((environment_id, approval_id))
}

async fn assert_queued_gate_concluded(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
    expected_gate_state: &str,
) -> TestResult {
    let row: (String, String, String, i64, String, bool, bool) = sqlx::query_as(
        r"
        SELECT attempt.lifecycle, gate.state, run.status,
               (SELECT count(*) FROM attempt_cancellation_intents
                WHERE attempt_id = attempt.id),
               terminal.terminal_authority,
               terminal.server_cancellation_operation_id = cancellation.operation_id,
               terminal.server_cancellation_digest =
                   automata_server_cancellation_terminal_digest(
                       cancellation.attempt_id, cancellation.operation_id,
                       cancellation.requested_by, cancellation.reason,
                       cancellation.requested_at_ms
                   )
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN job_environment_gates AS gate ON gate.attempt_id = attempt.id
        JOIN attempt_cancellation_intents AS cancellation
          ON cancellation.attempt_id = attempt.id
        JOIN attempt_terminal_results AS terminal
          ON terminal.attempt_id = attempt.id
        WHERE attempt.id = $1
        ",
    )
    .bind(queued.attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(row.0, "cancelled");
    assert_eq!(row.1, expected_gate_state);
    assert_eq!(
        row.2, "in_progress",
        "logical result projection, not gate cancellation, owns run finalization"
    );
    assert_eq!(row.3, 1);
    assert_eq!(row.4, "server_cancellation");
    assert!(row.5);
    assert!(row.6);
    Ok(())
}

async fn backdate_gate(
    database: &TestDatabase,
    attempt_id: AttemptId,
    created_at_ms: i64,
) -> TestResult {
    let mut transaction = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("UPDATE job_environment_gates SET created_at_ms = $2 WHERE attempt_id = $1")
        .bind(attempt_id.as_uuid())
        .bind(created_at_ms)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

async fn seed_variable(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
    actor: &SecretActor,
    scope_kind: &str,
    environment_id: Option<Uuid>,
) -> TestResult<Uuid> {
    let variable_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let now = database_now_ms(database).await?;
    sqlx::query(
        r"
        INSERT INTO workflow_variables (
            tenant_id, repository_id, environment_id, id, scope_kind, canonical_name,
            status, created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, $4, $5, 'PENDING_CONFIG',
                  'provisioning', $6, $7, $7)
        ",
    )
    .bind(&queued.tenant)
    .bind(queued.repository_id.as_uuid())
    .bind(environment_id)
    .bind(variable_id)
    .bind(scope_kind)
    .bind(actor.principal_id)
    .bind(now)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_variable_versions (
            tenant_id, id, variable_id, version_number, value_object_key,
            value_ciphertext_sha256, value_size_bytes, value_media_type,
            envelope_schema, created_by_principal_id, created_at_ms
        ) VALUES (
            $1, $2, $3, 1, $4, $5, 16,
            'application/vnd.automata.encrypted-variable-value', 1, $6, $7
        )
        ",
    )
    .bind(&queued.tenant)
    .bind(version_id)
    .bind(variable_id)
    .bind(format!("variables/{variable_id}/1"))
    .bind(digest(0xa4).as_bytes().as_slice())
    .bind(actor.principal_id)
    .bind(now)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        UPDATE workflow_variables
        SET current_version_id = $3, current_version_number = 1,
            status = 'active', revision = 2,
            updated_by_principal_id = $4, updated_at_ms = $5
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(&queued.tenant)
    .bind(variable_id)
    .bind(version_id)
    .bind(actor.principal_id)
    .bind(now)
    .execute(database.pool())
    .await?;
    Ok(variable_id)
}

async fn seed_repository_variable(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
    actor: &SecretActor,
) -> TestResult<Uuid> {
    seed_variable(database, queued, actor, "repository", None).await
}

async fn seed_environment_variable(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
    actor: &SecretActor,
    environment_id: Uuid,
) -> TestResult<Uuid> {
    seed_variable(database, queued, actor, "environment", Some(environment_id)).await
}

async fn prepare_and_resolve_unprotected_gate(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
) -> TestResult {
    let now = database_now_ms(database).await?;
    let tenant = TenantScope::from_authenticated_tenant_id(&queued.tenant)?;
    assert_eq!(
        database
            .store()
            .prepare_job_environment(PrepareJobEnvironment::new(
                tenant.clone(),
                queued.attempt_id,
                None,
                queued.runtime_context_digest,
                JobEventTrust::Trusted,
                JobSourceKind::SameRepository,
                ReusableSecretPermission::None,
                Uuid::new_v4(),
                UnixMillis::new(now),
                UnixMillis::new(now + 300_000),
            )?)
            .await?,
        JobEnvironmentGateState::Resolving
    );
    assert_eq!(
        database
            .store()
            .resolve_job_credentials(&tenant, queued.attempt_id)
            .await?,
        JobEnvironmentGateState::Ready
    );
    Ok(())
}

async fn reclassify_secret_scope_for_precedence_test(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
    secret_id: Uuid,
    scope_kind: &str,
    environment_id: Option<Uuid>,
) -> TestResult {
    let repository_id = (scope_kind != "tenant").then_some(queued.repository_id.as_uuid());
    let mut transaction = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        r"
        UPDATE secrets
        SET canonical_name = 'AUTHORITY_TOKEN_0', scope_kind = $3,
            repository_id = $4, environment_id = $5
        WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(&queued.tenant)
    .bind(secret_id)
    .bind(scope_kind)
    .bind(repository_id)
    .bind(environment_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE secret_policies
        SET secret_scope_kind = $3,
            tenant_repository_access_mode = CASE
                WHEN $3 = 'tenant' THEN 'all_repositories'
                ELSE tenant_repository_access_mode
            END
        WHERE tenant_id = $1 AND secret_id = $2
        ",
    )
    .bind(&queued.tenant)
    .bind(secret_id)
    .bind(scope_kind)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn prepare_ready_protected_secret_gate(
    database: &TestDatabase,
    initial_scope: &str,
) -> TestResult<(QueuedExecutionFixture, SecretActor, Uuid)> {
    let selected = BindingIdentity::fresh();
    let requirements = JobCredentialRequirements::new(
        JobEnvironmentRequirement::Environment(digest(0x94)),
        ["AUTHORITY_TOKEN_0".to_owned()],
        [],
    )?;
    let queued = seed_queued_execution(database, vec![selected], requirements).await?;
    let now = database_now_ms(database).await?;
    let actor = seed_secret_actor(database.pool(), &queued.tenant, now).await?;
    activate_builtin_provider(database.pool(), &queued.tenant, now).await?;
    seed_repository_secret(database.pool(), queued.repository_id, &actor, selected, 0).await?;
    if initial_scope == "tenant" {
        reclassify_secret_scope_for_precedence_test(
            database,
            &queued,
            selected.secret_id,
            "tenant",
            None,
        )
        .await?;
    }
    let (environment_id, _) =
        prepare_protected_environment_gate(database, &queued, &actor, now + 300_000).await?;
    assert_eq!(
        database
            .store()
            .review_job_environment(ReviewJobEnvironment::new(
                actor.actor(),
                queued.repository_id,
                queued.attempt_id,
                EnvironmentReviewDecision::Approve,
            )?)
            .await?,
        JobEnvironmentGateState::Resolving
    );
    let tenant = TenantScope::from_authenticated_tenant_id(&queued.tenant)?;
    assert_eq!(
        database
            .store()
            .resolve_job_credentials(&tenant, queued.attempt_id)
            .await?,
        JobEnvironmentGateState::Ready
    );
    Ok((queued, actor, environment_id))
}

async fn seed_higher_precedence_secret(
    database: &TestDatabase,
    queued: &QueuedExecutionFixture,
    actor: &SecretActor,
    scope_kind: &str,
    environment_id: Option<Uuid>,
) -> TestResult<BindingIdentity> {
    let higher = BindingIdentity::fresh();
    let index = usize::from(scope_kind != "repository");
    seed_repository_secret(database.pool(), queued.repository_id, actor, higher, index).await?;
    if scope_kind != "repository" {
        reclassify_secret_scope_for_precedence_test(
            database,
            queued,
            higher.secret_id,
            scope_kind,
            environment_id,
        )
        .await?;
    }
    Ok(higher)
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn protected_environment_rejection_is_atomic_and_review_replay_is_exact() -> TestResult {
    run_with_database(|database| async move {
        let requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::Environment(digest(0x91)),
            [],
            [],
        )?;
        let queued = seed_queued_execution(&database, Vec::new(), requirements).await?;
        let now = database_now_ms(&database).await?;
        let reviewer = seed_secret_actor(database.pool(), &queued.tenant, now).await?;
        let (_environment_id, approval_id) = prepare_protected_environment_gate(
            &database,
            &queued,
            &reviewer,
            now + 300_000,
        )
        .await?;
        let rejection = ReviewJobEnvironment::new(
            reviewer.actor(),
            queued.repository_id,
            queued.attempt_id,
            EnvironmentReviewDecision::Reject,
        )?;
        assert_eq!(
            database
                .store()
                .review_job_environment(rejection.clone())
                .await?,
            JobEnvironmentGateState::Rejected
        );
        assert_queued_gate_concluded(&database, &queued, "rejected").await?;

        assert_eq!(
            database
                .store()
                .review_job_environment(rejection)
                .await?,
            JobEnvironmentGateState::Rejected,
            "an exact same-principal and same-decision retry must replay"
        );
        let opposite = ReviewJobEnvironment::new(
            reviewer.actor(),
            queued.repository_id,
            queued.attempt_id,
            EnvironmentReviewDecision::Approve,
        )?;
        assert!(matches!(
            database.store().review_job_environment(opposite).await,
            Err(ProtectedEnvironmentStoreError::Conflict)
        ));

        let other = seed_secret_actor(database.pool(), &queued.tenant, now).await?;
        let no_prior_decision = ReviewJobEnvironment::new(
            other.actor(),
            queued.repository_id,
            queued.attempt_id,
            EnvironmentReviewDecision::Reject,
        )?;
        assert!(matches!(
            database
                .store()
                .review_job_environment(no_prior_decision)
                .await,
            Err(ProtectedEnvironmentStoreError::Conflict)
        ));
        let decisions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM protected_environment_approval_decisions WHERE tenant_id = $1 AND request_id = $2",
        )
        .bind(&queued.tenant)
        .bind(approval_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(decisions, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn unknown_requester_cannot_approve_self_review_separated_environment() -> TestResult {
    run_with_database(|database| async move {
        let requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::Environment(digest(0x96)),
            [],
            [],
        )?;
        let queued = seed_queued_execution(&database, Vec::new(), requirements).await?;
        let now = database_now_ms(&database).await?;
        let reviewer = seed_secret_actor(database.pool(), &queued.tenant, now).await?;
        let (_, approval_id) = prepare_protected_environment_gate_with_self_review(
            &database,
            &queued,
            &reviewer,
            now + 300_000,
            true,
        )
        .await?;
        let requester: Option<Uuid> = sqlx::query_scalar(
            "SELECT requested_by_principal_id FROM protected_environment_approval_requests WHERE tenant_id = $1 AND id = $2",
        )
        .bind(&queued.tenant)
        .bind(approval_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(requester, None, "push admission has no exact human requester");

        let mut transaction = database.pool().begin().await?;
        let error = sqlx::query(
            r"
            INSERT INTO protected_environment_approval_decisions (
                tenant_id, request_id, principal_id, decision, decided_at_ms
            ) VALUES ($1, $2, $3, 'approve', $4)
            ",
        )
        .bind(&queued.tenant)
        .bind(approval_id)
        .bind(reviewer.principal_id)
        .bind(database_now_ms(&database).await?)
        .execute(&mut *transaction)
        .await
        .expect_err("NULL requester must reject approval");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("protected_environment_approval_requester_required")
        );
        transaction.rollback().await?;

        let approve = ReviewJobEnvironment::new(
            reviewer.actor(),
            queued.repository_id,
            queued.attempt_id,
            EnvironmentReviewDecision::Approve,
        )?;
        assert!(matches!(
            database.store().review_job_environment(approve).await,
            Err(ProtectedEnvironmentStoreError::AuthorityRejected)
        ));
        let reject = ReviewJobEnvironment::new(
            reviewer.actor(),
            queued.repository_id,
            queued.attempt_id,
            EnvironmentReviewDecision::Reject,
        )?;
        assert_eq!(
            database.store().review_job_environment(reject).await?,
            JobEnvironmentGateState::Rejected
        );
        assert_queued_gate_concluded(&database, &queued, "rejected").await?;
        let (status, current): (String, bool) = sqlx::query_as(
            r"
            SELECT status,
                   automata_protected_environment_approval_is_current(
                       tenant_id, id,
                       floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
                   )
            FROM protected_environment_approval_requests
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&queued.tenant)
        .bind(approval_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(status, "rejected");
        assert!(!current, "unknown-requester approval can never become current");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn database_time_expires_waiting_and_unprepared_gates_and_replays_conclusion() -> TestResult {
    const GATE_LIFETIME_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;

    run_with_database(|database| async move {
        let requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::Environment(digest(0x92)),
            [],
            [],
        )?;
        let waiting = seed_queued_execution(&database, Vec::new(), requirements.clone()).await?;
        let tenant = TenantScope::from_authenticated_tenant_id(&waiting.tenant)?;
        let now = database_now_ms(&database).await?;
        let reviewer = seed_secret_actor(database.pool(), &waiting.tenant, now).await?;
        let (_, approval_id) = prepare_protected_environment_gate(
            &database,
            &waiting,
            &reviewer,
            now + 300_000,
        )
        .await?;
        assert_eq!(
            database
                .store()
                .inspect_job_environment_gate(&tenant, waiting.attempt_id)
                .await?
                .phase(),
            JobEnvironmentGatePhase::Waiting
        );
        let database_now = database_now_ms(&database).await?;
        let mut transaction = database.pool().begin().await?;
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE protected_environment_approval_requests SET expires_at_ms = $3 WHERE tenant_id = $1 AND id = $2",
        )
        .bind(&waiting.tenant)
        .bind(approval_id)
        .bind(database_now)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let expired_review = ReviewJobEnvironment::new(
            reviewer.actor(),
            waiting.repository_id,
            waiting.attempt_id,
            EnvironmentReviewDecision::Approve,
        )?;
        assert!(matches!(
            database
                .store()
                .review_job_environment(expired_review.clone())
                .await,
            Err(ProtectedEnvironmentStoreError::Conflict)
        ));
        assert!(matches!(
            database
                .store()
                .review_job_environment(expired_review)
                .await,
            Err(ProtectedEnvironmentStoreError::Conflict)
        ));
        assert_queued_gate_concluded(&database, &waiting, "expired").await?;
        let decisions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM protected_environment_approval_decisions WHERE tenant_id = $1 AND request_id = $2",
        )
        .bind(&waiting.tenant)
        .bind(approval_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(decisions, 0, "expired review must not retain a decision");
        database
            .store()
            .conclude_terminal_job_environment(&tenant, waiting.attempt_id)
            .await?;
        database
            .store()
            .conclude_terminal_job_environment(&tenant, waiting.attempt_id)
            .await?;

        let unprepared = seed_queued_execution(&database, Vec::new(), requirements).await?;
        let unprepared_tenant = TenantScope::from_authenticated_tenant_id(&unprepared.tenant)?;
        let now = database_now_ms(&database).await?;
        backdate_gate(
            &database,
            unprepared.attempt_id,
            now - GATE_LIFETIME_MILLIS + 60_000,
        )
        .await?;
        assert_eq!(
            database
                .store()
                .inspect_job_environment_gate(&unprepared_tenant, unprepared.attempt_id)
                .await?
                .phase(),
            JobEnvironmentGatePhase::SelectionPending
        );
        backdate_gate(
            &database,
            unprepared.attempt_id,
            now - GATE_LIFETIME_MILLIS - 1,
        )
        .await?;
        assert_eq!(
            database
                .store()
                .inspect_job_environment_gate(&unprepared_tenant, unprepared.attempt_id)
                .await?
                .phase(),
            JobEnvironmentGatePhase::Terminal
        );
        assert_queued_gate_concluded(&database, &unprepared, "cancelled").await?;
        database
            .store()
            .conclude_terminal_job_environment(&unprepared_tenant, unprepared.attempt_id)
            .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn terminal_conclusion_accepts_only_exact_canonical_prior_cancellation() -> TestResult {
    run_with_database(|database| async move {
        let requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::Environment(digest(0x97)),
            [],
            [],
        )?;
        let prior = seed_queued_execution(&database, Vec::new(), requirements.clone()).await?;
        let prior_request = RequestCancellation::new(
            OperationId::new(),
            prior.attempt_id,
            CancellationActor::new("operator")?,
            Some(CancellationReason::new(
                "operator cancelled protected environment work",
            )?),
            UnixMillis::new(database_now_ms(&database).await?),
        );
        let cancellation = database
            .store()
            .request_cancellation(prior_request.clone())
            .await?;
        assert!(!cancellation.was_replayed());
        assert!(cancellation.delivery().is_none());
        assert_eq!(cancellation.request(), &prior_request);
        let tenant = TenantScope::from_authenticated_tenant_id(&prior.tenant)?;
        database
            .store()
            .conclude_terminal_job_environment(&tenant, prior.attempt_id)
            .await?;
        database
            .store()
            .conclude_terminal_job_environment(&tenant, prior.attempt_id)
            .await?;
        assert_queued_gate_concluded(&database, &prior, "cancelled").await?;
        let retained_actor: String = sqlx::query_scalar(
            "SELECT requested_by FROM attempt_cancellation_intents WHERE attempt_id = $1",
        )
        .bind(prior.attempt_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(retained_actor, "operator");

        let corrupt = seed_queued_execution(&database, Vec::new(), requirements).await?;
        let corrupt_now = database_now_ms(&database).await?;
        let mut transaction = database.pool().begin().await?;
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            r"
            INSERT INTO attempt_cancellation_intents (
                attempt_id, operation_id, requested_by, reason, requested_at_ms,
                delivery_session_id, delivery_command_sequence
            ) VALUES ($1, $2, 'operator', 'uncanonical cancellation', $3, NULL, NULL)
            ",
        )
        .bind(corrupt.attempt_id.as_uuid())
        .bind(OperationId::new().as_uuid())
        .bind(corrupt_now)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE job_attempts SET lifecycle = 'cancelled', changed_at_ms = $2 WHERE id = $1",
        )
        .bind(corrupt.attempt_id.as_uuid())
        .bind(corrupt_now)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            UPDATE job_environment_gates
            SET state = 'cancelled', updated_at_ms = $2, revision = revision + 1
            WHERE attempt_id = $1
            ",
        )
        .bind(corrupt.attempt_id.as_uuid())
        .bind(corrupt_now)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let corrupt_tenant = TenantScope::from_authenticated_tenant_id(&corrupt.tenant)?;
        assert!(matches!(
            database
                .store()
                .conclude_terminal_job_environment(&corrupt_tenant, corrupt.attempt_id)
                .await,
            Err(ProtectedEnvironmentStoreError::CorruptData)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn stale_ready_environment_secret_and_variable_snapshots_are_concluded() -> TestResult {
    run_with_database(|database| async move {
        let protected_requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::Environment(digest(0x93)),
            [],
            [],
        )?;
        let protected =
            seed_queued_execution(&database, Vec::new(), protected_requirements).await?;
        let now = database_now_ms(&database).await?;
        let reviewer = seed_secret_actor(database.pool(), &protected.tenant, now).await?;
        let (environment_id, _) =
            prepare_protected_environment_gate(&database, &protected, &reviewer, now + 300_000)
                .await?;
        assert_eq!(
            database
                .store()
                .review_job_environment(ReviewJobEnvironment::new(
                    reviewer.actor(),
                    protected.repository_id,
                    protected.attempt_id,
                    EnvironmentReviewDecision::Approve,
                )?)
                .await?,
            JobEnvironmentGateState::Resolving
        );
        let protected_tenant = TenantScope::from_authenticated_tenant_id(&protected.tenant)?;
        assert_eq!(
            database
                .store()
                .resolve_job_credentials(&protected_tenant, protected.attempt_id)
                .await?,
            JobEnvironmentGateState::Ready
        );
        sqlx::query(
            r"
            UPDATE repository_environments
            SET required_approvals = 2, revision = 2, updated_at_ms = $4
            WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
            ",
        )
        .bind(&protected.tenant)
        .bind(protected.repository_id.as_uuid())
        .bind(environment_id)
        .bind(database_now_ms(&database).await?)
        .execute(database.pool())
        .await?;
        assert_eq!(
            database
                .store()
                .inspect_job_environment_gate(&protected_tenant, protected.attempt_id)
                .await?
                .phase(),
            JobEnvironmentGatePhase::Terminal
        );
        database
            .store()
            .conclude_terminal_job_environment(&protected_tenant, protected.attempt_id)
            .await?;
        assert_queued_gate_concluded(&database, &protected, "ready").await?;

        let binding = BindingIdentity::fresh();
        let secret_requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::None,
            ["AUTHORITY_TOKEN_0".to_owned()],
            [],
        )?;
        let secret = seed_queued_execution(&database, vec![binding], secret_requirements).await?;
        let now = database_now_ms(&database).await?;
        let secret_actor = seed_secret_actor(database.pool(), &secret.tenant, now).await?;
        activate_builtin_provider(database.pool(), &secret.tenant, now).await?;
        seed_repository_secret(
            database.pool(),
            secret.repository_id,
            &secret_actor,
            binding,
            0,
        )
        .await?;
        prepare_and_resolve_unprotected_gate(&database, &secret).await?;
        sqlx::query(
            r"
            UPDATE secrets
            SET status = 'disabled', revision = revision + 1,
                updated_by_principal_id = $3, updated_at_ms = $4
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&secret.tenant)
        .bind(binding.secret_id)
        .bind(secret_actor.principal_id)
        .bind(database_now_ms(&database).await?)
        .execute(database.pool())
        .await?;
        let secret_tenant = TenantScope::from_authenticated_tenant_id(&secret.tenant)?;
        assert_eq!(
            database
                .store()
                .inspect_job_environment_gate(&secret_tenant, secret.attempt_id)
                .await?
                .phase(),
            JobEnvironmentGatePhase::Terminal
        );
        assert_queued_gate_concluded(&database, &secret, "ready").await?;

        let variable_requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::None,
            [],
            ["PENDING_CONFIG".to_owned()],
        )?;
        let variable = seed_queued_execution(&database, Vec::new(), variable_requirements).await?;
        let now = database_now_ms(&database).await?;
        let variable_actor = seed_secret_actor(database.pool(), &variable.tenant, now).await?;
        let variable_id = seed_repository_variable(&database, &variable, &variable_actor).await?;
        prepare_and_resolve_unprotected_gate(&database, &variable).await?;
        sqlx::query(
            r"
            UPDATE workflow_variables
            SET status = 'disabled', revision = revision + 1,
                updated_by_principal_id = $3, updated_at_ms = $4
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&variable.tenant)
        .bind(variable_id)
        .bind(variable_actor.principal_id)
        .bind(database_now_ms(&database).await?)
        .execute(database.pool())
        .await?;
        let variable_tenant = TenantScope::from_authenticated_tenant_id(&variable.tenant)?;
        assert_eq!(
            database
                .store()
                .inspect_job_environment_gate(&variable_tenant, variable.attempt_id)
                .await?
                .phase(),
            JobEnvironmentGatePhase::Terminal
        );
        assert_queued_gate_concluded(&database, &variable, "ready").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn stale_resolving_approval_and_environment_are_atomically_concluded() -> TestResult {
    run_with_database(|database| async move {
        for stale_kind in [
            "environment_revision",
            "environment_disable",
            "approval_expiry",
            "reviewer_revocation",
        ] {
            let requirements = JobCredentialRequirements::new(
                JobEnvironmentRequirement::Environment(digest(0x95)),
                [],
                [],
            )?;
            let queued = seed_queued_execution(&database, Vec::new(), requirements).await?;
            let now = database_now_ms(&database).await?;
            let reviewer = seed_secret_actor(database.pool(), &queued.tenant, now).await?;
            let (environment_id, approval_id) = prepare_protected_environment_gate(
                &database,
                &queued,
                &reviewer,
                now + 300_000,
            )
            .await?;
            let approval_review = ReviewJobEnvironment::new(
                reviewer.actor(),
                queued.repository_id,
                queued.attempt_id,
                EnvironmentReviewDecision::Approve,
            )?;
            assert_eq!(
                database
                    .store()
                    .review_job_environment(approval_review.clone())
                    .await?,
                JobEnvironmentGateState::Resolving
            );

            match stale_kind {
                "environment_revision" => {
                    sqlx::query(
                        r"
                        UPDATE repository_environments
                        SET required_approvals = 2, revision = revision + 1, updated_at_ms = $4
                        WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
                        ",
                    )
                    .bind(&queued.tenant)
                    .bind(queued.repository_id.as_uuid())
                    .bind(environment_id)
                    .bind(database_now_ms(&database).await?)
                    .execute(database.pool())
                    .await?;
                }
                "environment_disable" => {
                    sqlx::query(
                        r"
                        UPDATE repository_environments
                        SET status = 'disabled', revision = revision + 1, updated_at_ms = $4
                        WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
                        ",
                    )
                    .bind(&queued.tenant)
                    .bind(queued.repository_id.as_uuid())
                    .bind(environment_id)
                    .bind(database_now_ms(&database).await?)
                    .execute(database.pool())
                    .await?;
                }
                "approval_expiry" => {
                    let mut transaction = database.pool().begin().await?;
                    sqlx::query("SET LOCAL session_replication_role = replica")
                        .execute(&mut *transaction)
                        .await?;
                    sqlx::query(
                        "UPDATE protected_environment_approval_requests SET expires_at_ms = $3 WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(&queued.tenant)
                    .bind(approval_id)
                    .bind(database_now_ms(&database).await?)
                    .execute(&mut *transaction)
                    .await?;
                    transaction.commit().await?;
                }
                "reviewer_revocation" => {
                    let current_revision: i64 = sqlx::query_scalar(
                        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
                    )
                    .bind(&queued.tenant)
                    .bind(reviewer.principal_id)
                    .fetch_one(database.pool())
                    .await?;
                    sqlx::query(
                        r"
                        UPDATE tenant_human_memberships
                        SET authorization_revision = $3, updated_at_ms = $4
                        WHERE tenant_id = $1 AND principal_id = $2
                        ",
                    )
                    .bind(&queued.tenant)
                    .bind(reviewer.principal_id)
                    .bind(current_revision + 1)
                    .bind(database_now_ms(&database).await?)
                    .execute(database.pool())
                    .await?;
                }
                _ => unreachable!(),
            }

            let tenant = TenantScope::from_authenticated_tenant_id(&queued.tenant)?;
            assert_eq!(
                database
                    .store()
                    .resolve_job_credentials(&tenant, queued.attempt_id)
                    .await?,
                JobEnvironmentGateState::Cancelled,
                "{stale_kind} must close resolving rather than poison the queue"
            );
            assert_queued_gate_concluded(&database, &queued, "cancelled").await?;
            let stale_review = database
                .store()
                .review_job_environment(approval_review)
                .await;
            let expected = if stale_kind == "reviewer_revocation" {
                matches!(
                    stale_review,
                    Err(ProtectedEnvironmentStoreError::AuthorityRejected)
                )
            } else {
                matches!(stale_review, Err(ProtectedEnvironmentStoreError::Conflict))
            };
            assert!(expected, "{stale_kind} stale review returned {stale_review:?}");
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn ready_authority_is_rechecked_at_inspection_lease_and_grant_boundaries() -> TestResult {
    run_with_database(|database| async move {
        for (initial_scope, higher_scope) in [
            ("repository", "environment"),
            ("tenant", "repository"),
            ("tenant", "environment"),
        ] {
            let (queued, actor, environment_id) =
                prepare_ready_protected_secret_gate(&database, initial_scope).await?;
            seed_higher_precedence_secret(
                &database,
                &queued,
                &actor,
                higher_scope,
                (higher_scope == "environment").then_some(environment_id),
            )
            .await?;
            let tenant = TenantScope::from_authenticated_tenant_id(&queued.tenant)?;
            assert_eq!(
                database
                    .store()
                    .inspect_job_environment_gate(&tenant, queued.attempt_id)
                    .await?
                    .phase(),
                JobEnvironmentGatePhase::Terminal,
                "{initial_scope} selection must be invalidated by {higher_scope} shadow"
            );
            assert_queued_gate_concluded(&database, &queued, "ready").await?;
        }

        let (lease_guarded, actor, environment_id) =
            prepare_ready_protected_secret_gate(&database, "repository").await?;
        seed_higher_precedence_secret(
            &database,
            &lease_guarded,
            &actor,
            "environment",
            Some(environment_id),
        )
        .await?;
        let Err(lease_error) = lease_execution(&database, lease_guarded).await else {
            return Err("lease authority accepted a shadowed secret selection".into());
        };
        assert!(
            lease_error
                .to_string()
                .contains("job environment and credential authority is no longer current"),
            "unexpected lease rejection: {lease_error}"
        );

        let variable_requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::Environment(digest(0x96)),
            [],
            ["PENDING_CONFIG".to_owned()],
        )?;
        let variable_shadow =
            seed_queued_execution(&database, Vec::new(), variable_requirements).await?;
        let now = database_now_ms(&database).await?;
        let variable_actor = seed_secret_actor(database.pool(), &variable_shadow.tenant, now).await?;
        seed_repository_variable(&database, &variable_shadow, &variable_actor).await?;
        let (variable_environment_id, _) = prepare_protected_environment_gate(
            &database,
            &variable_shadow,
            &variable_actor,
            now + 300_000,
        )
        .await?;
        assert_eq!(
            database
                .store()
                .review_job_environment(ReviewJobEnvironment::new(
                    variable_actor.actor(),
                    variable_shadow.repository_id,
                    variable_shadow.attempt_id,
                    EnvironmentReviewDecision::Approve,
                )?)
                .await?,
            JobEnvironmentGateState::Resolving
        );
        let variable_tenant =
            TenantScope::from_authenticated_tenant_id(&variable_shadow.tenant)?;
        assert_eq!(
            database
                .store()
                .resolve_job_credentials(&variable_tenant, variable_shadow.attempt_id)
                .await?,
            JobEnvironmentGateState::Ready
        );
        seed_environment_variable(
            &database,
            &variable_shadow,
            &variable_actor,
            variable_environment_id,
        )
        .await?;
        // Variable value custody is independently fail-closed. Disable only
        // that earlier guard so this case reaches the 0070 currentness proof.
        sqlx::query(
            "ALTER TABLE job_attempts DISABLE TRIGGER job_attempts_00_require_variable_custody_before_lease",
        )
        .execute(database.pool())
        .await?;
        let variable_lease = lease_execution(&database, variable_shadow).await;
        sqlx::query(
            "ALTER TABLE job_attempts ENABLE TRIGGER job_attempts_00_require_variable_custody_before_lease",
        )
        .execute(database.pool())
        .await?;
        let Err(variable_lease_error) = variable_lease else {
            return Err("lease authority accepted a shadowed variable selection".into());
        };
        assert!(
            variable_lease_error
                .to_string()
                .contains("job environment and credential authority is no longer current"),
            "unexpected variable lease rejection: {variable_lease_error}"
        );

        let (grant_guarded, actor, environment_id) =
            prepare_ready_protected_secret_gate(&database, "repository").await?;
        seed_higher_precedence_secret(
            &database,
            &grant_guarded,
            &actor,
            "environment",
            Some(environment_id),
        )
        .await?;
        // Bypass only the new lease-time guard so this independent case can
        // prove grant issuance enforces the same precedence boundary.
        sqlx::query(
            "ALTER TABLE job_attempts DISABLE TRIGGER job_attempts_01_require_current_environment_gate_before_lease",
        )
        .execute(database.pool())
        .await?;
        let execution = lease_execution(&database, grant_guarded).await?;
        sqlx::query(
            "ALTER TABLE job_attempts ENABLE TRIGGER job_attempts_01_require_current_environment_gate_before_lease",
        )
        .execute(database.pool())
        .await?;
        let tenant = TenantScope::from_authenticated_tenant_id(&execution.tenant)?;
        let issue = IssueLeasedJobSecretGrants::new(
            tenant,
            execution.lease.attempt_id(),
            execution.lease.lease_id(),
            execution.lease.fencing_token(),
            execution.lease.issued_at(),
            execution.lease.expires_at(),
        )?;
        assert!(matches!(
            database.store().issue_leased_job_secret_grants(issue).await,
            Err(ProtectedEnvironmentStoreError::AuthorityRejected)
        ));

        // Missing-name resolution is an intentional immutable snapshot: a
        // secret created later does not retroactively inject a credential into
        // the already-resolved job.
        let late_binding = BindingIdentity::fresh();
        let missing_requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::None,
            ["AUTHORITY_TOKEN_0".to_owned()],
            [],
        )?;
        let missing =
            seed_queued_execution(&database, vec![late_binding], missing_requirements).await?;
        prepare_and_resolve_unprotected_gate(&database, &missing).await?;
        let now = database_now_ms(&database).await?;
        let late_actor = seed_secret_actor(database.pool(), &missing.tenant, now).await?;
        activate_builtin_provider(database.pool(), &missing.tenant, now).await?;
        seed_repository_secret(
            database.pool(),
            missing.repository_id,
            &late_actor,
            late_binding,
            0,
        )
        .await?;
        let missing_tenant = TenantScope::from_authenticated_tenant_id(&missing.tenant)?;
        assert_eq!(
            database
                .store()
                .inspect_job_environment_gate(&missing_tenant, missing.attempt_id)
                .await?
                .phase(),
            JobEnvironmentGatePhase::Ready
        );
        lease_execution(&database, missing).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn in_flight_environment_authority_change_is_linearized_before_lease() -> TestResult {
    run_with_database(|database| async move {
        let (queued, _actor, environment_id) =
            prepare_ready_protected_secret_gate(&database, "repository").await?;
        let attempt_id = queued.attempt_id;
        let mut transaction = database.pool().begin().await?;
        let blocking_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *transaction)
            .await?;
        let changed = sqlx::query(
            r"
            UPDATE repository_environments
            SET required_approvals = 2, revision = revision + 1, updated_at_ms = $4
            WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
            ",
        )
        .bind(&queued.tenant)
        .bind(queued.repository_id.as_uuid())
        .bind(environment_id)
        .bind(database_now_ms(&database).await?)
        .execute(&mut *transaction)
        .await?;
        assert_eq!(changed.rows_affected(), 1);

        let lease_database = Arc::clone(&database);
        let lease = tokio::spawn(async move { lease_execution(&lease_database, queued).await });
        wait_for_backend_blocked_by(database.pool(), blocking_backend_pid).await?;
        let lifecycle_while_blocked: String =
            sqlx::query_scalar("SELECT lifecycle FROM job_attempts WHERE id = $1")
                .bind(attempt_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(lifecycle_while_blocked, "queued");

        transaction.commit().await?;
        let lease_result = tokio::time::timeout(Duration::from_secs(5), lease).await??;
        let Err(lease_error) = lease_result else {
            return Err("lease accepted authority that changed while its guard was blocked".into());
        };
        assert!(
            lease_error
                .to_string()
                .contains("job environment and credential authority is no longer current"),
            "unexpected lease rejection: {lease_error}"
        );
        let lifecycle_after_rejection: String =
            sqlx::query_scalar("SELECT lifecycle FROM job_attempts WHERE id = $1")
                .bind(attempt_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(lifecycle_after_rejection, "queued");
        Ok(())
    })
    .await
}

async fn insert_workload_grant(
    pool: &PgPool,
    execution: &ExecutionFixture,
    binding: BindingIdentity,
    environment_id: Option<Uuid>,
    approval_id: Option<Uuid>,
    digest_byte: u8,
) -> TestResult {
    let mut transaction = pool.begin().await?;
    insert_workload_grant_in_transaction(
        &mut transaction,
        execution,
        binding,
        environment_id,
        approval_id,
        digest_byte,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn insert_workload_grant_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    execution: &ExecutionFixture,
    binding: BindingIdentity,
    environment_id: Option<Uuid>,
    approval_id: Option<Uuid>,
    digest_byte: u8,
) -> TestResult {
    let issued_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await?;
    let mut authority_digest = Sha256::new();
    authority_digest.update(binding.grant_id.as_bytes());
    authority_digest.update([digest_byte]);
    let authority_digest = authority_digest.finalize();
    sqlx::query(
        r"
        INSERT INTO secret_workload_grants (
            tenant_id, repository_id, run_id, job_id, attempt_id, id,
            fencing_token, secret_id, secret_version_id, secret_version_number,
            provider_id, environment_id, environment_approval_request_id,
            grant_mode, event_trust, source_kind, authority_digest,
            authority_digest_key_id, status, issued_at_ms, expires_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, 1,
            'builtin', $10, $11, 'readable_secret', 'trusted',
            'same_repository', $12, $13, 'active', $14, $15
        )
        ",
    )
    .bind(&execution.tenant)
    .bind(execution.repository_id.as_uuid())
    .bind(execution.run_id.as_uuid())
    .bind(execution.job_id.as_uuid())
    .bind(execution.lease.attempt_id().as_uuid())
    .bind(binding.grant_id)
    .bind(i64::try_from(execution.lease.fencing_token().get())?)
    .bind(binding.secret_id)
    .bind(binding.version_id)
    .bind(environment_id)
    .bind(approval_id)
    .bind(authority_digest.as_slice())
    .bind(format!("authority-test-key-{digest_byte}"))
    .bind(issued_at)
    .bind(execution.time(300_500))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn seed_authority_state(
    database: &TestDatabase,
    execution: &ExecutionFixture,
    protected: bool,
    insert_grant: bool,
) -> TestResult<(SecretActor, Option<Uuid>, Option<Uuid>)> {
    let actor = seed_secret_actor(
        database.pool(),
        &execution.tenant,
        execution.lease.issued_at().get(),
    )
    .await?;
    activate_builtin_provider(database.pool(), &execution.tenant, execution.time(100_000)).await?;
    for (index, binding) in execution.bindings.iter().copied().enumerate() {
        seed_repository_secret(
            database.pool(),
            execution.repository_id,
            &actor,
            binding,
            index,
        )
        .await?;
    }
    let (environment_id, approval_id) =
        seed_environment(database.pool(), execution, &actor, protected).await?;
    if insert_grant {
        for (index, binding) in execution.bindings.iter().copied().enumerate() {
            insert_workload_grant(
                database.pool(),
                execution,
                binding,
                Some(environment_id),
                approval_id,
                u8::try_from(index + 1)?,
            )
            .await?;
        }
    }
    Ok((actor, Some(environment_id), approval_id))
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn protected_environment_issues_only_exact_server_derived_lease_bindings() -> TestResult {
    run_with_database(|database| async move {
        let binding = BindingIdentity::fresh();
        let requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::None,
            ["AUTHORITY_TOKEN_0".to_owned()],
            [],
        )?;
        let queued = seed_queued_execution(&database, vec![binding], requirements).await?;
        let tenant = TenantScope::from_authenticated_tenant_id(&queued.tenant)?;
        let snapshot = database
            .store()
            .inspect_job_environment_gate(&tenant, queued.attempt_id)
            .await?;
        assert_eq!(snapshot.phase(), JobEnvironmentGatePhase::SelectionPending);
        assert_eq!(
            snapshot.runtime_context_digest(),
            queued.runtime_context_digest
        );
        assert_eq!(snapshot.variable_reference_count(), 0);
        let activation = snapshot.activation().expect("durable activation evidence");
        assert_eq!(activation.environment(), None);
        assert_eq!(activation.event_trust(), JobEventTrust::Trusted);
        assert_eq!(activation.source_kind(), JobSourceKind::SameRepository);
        assert_eq!(
            activation.reusable_secret_permission(),
            ReusableSecretPermission::None
        );
        let now = database_now_ms(&database).await?;
        let actor = seed_secret_actor(database.pool(), &queued.tenant, now).await?;
        activate_builtin_provider(database.pool(), &queued.tenant, now).await?;
        seed_repository_secret(database.pool(), queued.repository_id, &actor, binding, 0).await?;

        let approval_request_id = Uuid::new_v4();
        let prepare_request = |context_digest, source_kind| {
            PrepareJobEnvironment::new(
                tenant.clone(),
                queued.attempt_id,
                None,
                context_digest,
                JobEventTrust::Trusted,
                source_kind,
                ReusableSecretPermission::None,
                approval_request_id,
                UnixMillis::new(now),
                UnixMillis::new(now + 300_000),
            )
        };
        let prepare =
            prepare_request(queued.runtime_context_digest, JobSourceKind::SameRepository)?;
        let wrong_context = prepare_request(digest(0xff), JobSourceKind::SameRepository)?;
        assert!(matches!(
            database
                .store()
                .prepare_job_environment(wrong_context)
                .await,
            Err(ProtectedEnvironmentStoreError::AuthorityRejected)
        ));
        assert_eq!(
            database
                .store()
                .prepare_job_environment(prepare.clone())
                .await?,
            JobEnvironmentGateState::Resolving
        );
        assert_eq!(
            database
                .store()
                .prepare_job_environment(prepare.clone())
                .await?,
            JobEnvironmentGateState::Resolving
        );
        let conflicting_replay =
            prepare_request(queued.runtime_context_digest, JobSourceKind::Fork)?;
        assert!(matches!(
            database
                .store()
                .prepare_job_environment(conflicting_replay)
                .await,
            Err(ProtectedEnvironmentStoreError::Conflict)
        ));
        assert_eq!(
            database
                .store()
                .resolve_job_credentials(&tenant, queued.attempt_id)
                .await?,
            JobEnvironmentGateState::Ready
        );

        let execution = lease_execution(&database, queued).await?;
        let issue_request = |lease_id, fencing_token| {
            IssueLeasedJobSecretGrants::new(
                tenant.clone(),
                execution.lease.attempt_id(),
                lease_id,
                fencing_token,
                execution.lease.issued_at(),
                execution.lease.expires_at(),
            )
        };
        let exact_issue =
            issue_request(execution.lease.lease_id(), execution.lease.fencing_token())?;
        let wrong_fence = issue_request(
            execution.lease.lease_id(),
            FencingToken::new(execution.lease.fencing_token().get() + 1)?,
        )?;
        assert!(matches!(
            database
                .store()
                .issue_leased_job_secret_grants(wrong_fence)
                .await,
            Err(ProtectedEnvironmentStoreError::AuthorityRejected)
        ));
        let wrong_lease = issue_request(LeaseId::new(), execution.lease.fencing_token())?;
        assert!(matches!(
            database
                .store()
                .issue_leased_job_secret_grants(wrong_lease)
                .await,
            Err(ProtectedEnvironmentStoreError::AuthorityRejected)
        ));
        let premature_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM job_secret_bindings WHERE attempt_id = $1")
                .bind(execution.lease.attempt_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(premature_rows, 0);

        let issued = database
            .store()
            .issue_leased_job_secret_grants(exact_issue.clone())
            .await?;
        assert_eq!(issued.len(), 1);
        assert_eq!(issued[0].canonical_name(), "AUTHORITY_TOKEN_0");
        let expected_version_id = binding.version_id.hyphenated().to_string();
        assert_eq!(
            issued[0].binding().version_id(),
            Some(expected_version_id.as_str())
        );
        let issued_grant_id = Uuid::parse_str(issued[0].binding().binding_id())?;
        let durable: (Uuid, Uuid, i64, bool, String, Uuid) = sqlx::query_as(
            r"
            SELECT binding.grant_id, binding.lease_id, binding.fencing_token,
                   binding.binding_digest IS NOT DISTINCT FROM
                       automata_job_secret_binding_digest(
                           binding.attempt_id, binding.canonical_name,
                           binding.tenant_id, binding.grant_id,
                           binding.lease_id, binding.fencing_token
                       ),
                   workload_grant.authority_digest_key_id,
                   workload_grant.secret_version_id
            FROM job_secret_bindings AS binding
            JOIN secret_workload_grants AS workload_grant
              ON workload_grant.tenant_id = binding.tenant_id
             AND workload_grant.id = binding.grant_id
            WHERE binding.attempt_id = $1 AND binding.canonical_name = $2
            ",
        )
        .bind(execution.lease.attempt_id().as_uuid())
        .bind("AUTHORITY_TOKEN_0")
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable.0, issued_grant_id);
        assert_eq!(durable.1, execution.lease.lease_id().as_uuid());
        assert_eq!(
            durable.2,
            i64::try_from(execution.lease.fencing_token().get())?
        );
        assert!(durable.3);
        assert_eq!(durable.4, "leased-job-secret-grant-v1");
        assert_eq!(durable.5, binding.version_id);

        let replayed = database
            .store()
            .issue_leased_job_secret_grants(exact_issue)
            .await?;
        assert_eq!(replayed, issued);
        let durable_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM job_secret_bindings WHERE attempt_id = $1")
                .bind(execution.lease.attempt_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(durable_rows, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn variable_bearing_job_cannot_bypass_custody_at_lease_boundary() -> TestResult {
    run_with_database(|database| async move {
        let requirements = JobCredentialRequirements::new(
            JobEnvironmentRequirement::None,
            [],
            ["PENDING_CONFIG".to_owned()],
        )?;
        let queued = seed_queued_execution(&database, Vec::new(), requirements).await?;
        let tenant = TenantScope::from_authenticated_tenant_id(&queued.tenant)?;
        let now = database_now_ms(&database).await?;
        let request = PrepareJobEnvironment::new(
            tenant.clone(),
            queued.attempt_id,
            None,
            queued.runtime_context_digest,
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
            Uuid::new_v4(),
            UnixMillis::new(now),
            UnixMillis::new(now + 300_000),
        )?;
        assert_eq!(
            database.store().prepare_job_environment(request).await?,
            JobEnvironmentGateState::Resolving
        );
        assert_eq!(
            database
                .store()
                .resolve_job_credentials(&tenant, queued.attempt_id)
                .await?,
            JobEnvironmentGateState::Ready
        );

        let Err(error) = lease_execution(&database, queued).await else {
            return Err("variable-bearing attempt bypassed custody at lease time".into());
        };
        assert_eq!(
            error
                .downcast_ref::<sqlx::Error>()
                .and_then(sqlx::Error::as_database_error)
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("job_attempts_variable_custody_required"),
            "unexpected lease rejection: {error}",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn current_repository_binding_remains_closed_and_rejects_tamper() -> TestResult {
    run_with_database(|database| async move {
        let binding = BindingIdentity::fresh();
        let execution = seed_current_execution(&database, vec![binding]).await?;
        seed_authority_state(&database, &execution, false, true).await?;

        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(
                    execution.request(execution.exact_bindings(), 121_000)?,
                )
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "current rows must not issue a receipt without every durable and credential prerequisite",
        );

        let wrong_version = ManagedSecretBindingSet::new([ManagedSecretBinding::new(
            SecretWorkloadGrantId::from_uuid(binding.grant_id)?,
            RepositorySecretVersionId::from_uuid(Uuid::new_v4())?,
        )])?;
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(execution.request(wrong_version, 121_000)?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
        );
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(execution.request(
                    ManagedSecretBindingSet::new([])?,
                    121_000,
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "an exact runtime digest cannot smuggle a smaller grant set",
        );

        sqlx::query(
            r"
            UPDATE secret_workload_grants
            SET status = 'revoked', revoked_at_ms = $3,
                revocation_reason = 'administrative_revocation'
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(&execution.tenant)
        .bind(binding.grant_id)
        .bind(execution.time(121_000))
        .execute(database.pool())
        .await?;
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(
                    execution.request(execution.exact_bindings(), 121_100)?,
                )
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
        );

        let reactivated = sqlx::query(
            r"
            UPDATE secret_workload_grants
            SET status = 'active', revoked_at_ms = NULL, revocation_reason = NULL
            WHERE tenant_id = $1 AND id = $2 AND status = 'revoked'
            ",
        )
        .bind(&execution.tenant)
        .bind(binding.grant_id)
        .execute(database.pool())
        .await;
        assert_constraint(
            reactivated.expect_err("terminal grants must not reactivate"),
            "secret_workload_grants_terminal_monotonic",
        );

        let newer_attempt = sqlx::query(
            r"
            INSERT INTO job_attempts (
                id, job_id, attempt_number, lifecycle, fencing_token,
                lease_failures, queued_at_ms, changed_at_ms,
                secret_exposure_class, raw_log_disposition,
                requested_log_visibility, effective_log_visibility,
                output_safety_reason, output_safety_schema, classified_at_ms
            )
            SELECT $1, job_id, 2, 'queued', 0, 0, $3, $3,
                   secret_exposure_class, raw_log_disposition,
                   requested_log_visibility, effective_log_visibility,
                   output_safety_reason, output_safety_schema, $3
            FROM job_attempts WHERE id = $2
            ",
        )
        .bind(Uuid::new_v4())
        .bind(execution.lease.attempt_id().as_uuid())
        .bind(execution.time(121_200))
        .execute(database.pool())
        .await;
        assert_constraint(
            newer_attempt.expect_err("a job may have only one current attempt"),
            "job_attempts_one_current_per_job",
        );
        Ok(())
    })
    .await
}

fn assert_constraint(error: sqlx::Error, expected: &str) {
    let sqlx::Error::Database(error) = error else {
        panic!("expected database constraint failure");
    };
    assert_eq!(error.constraint(), Some(expected));
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn exact_delivery_operation_is_reserved_and_replayed_without_values() -> TestResult {
    run_with_database(|database| async move {
        let binding = BindingIdentity::fresh();
        let execution = seed_current_execution(&database, vec![binding]).await?;
        seed_authority_state(&database, &execution, false, true).await?;
        let operation_id = Uuid::new_v4();
        let verifier = digest(0xd1);
        let first = database
            .store()
            .resolve_managed_secret_authority(execution.delivery_request(
                121_000,
                operation_id,
                verifier,
            )?)
            .await?;
        assert_eq!(first.operation_id().as_uuid(), operation_id);
        assert_eq!(first.bindings().len(), 1);
        assert_eq!(
            first.bindings()[0].version_id().as_uuid(),
            binding.version_id
        );

        let replay_request = execution.authenticated_delivery_request(
            121_100,
            operation_id,
            verifier,
        )?;
        let replay = database
            .store()
            .resolve_managed_secret_authority(replay_request.clone())
            .await?;
        assert_eq!(replay.operation_id(), first.operation_id());
        assert_eq!(replay.evidence_digest(), first.evidence_digest());

        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(execution.delivery_request(
                    121_100,
                    operation_id,
                    digest(0xd2),
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "an existing operation cannot be replayed with another bearer verifier",
        );
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(execution.delivery_request(
                    121_100,
                    Uuid::new_v4(),
                    digest(0xd3),
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "one exact workload cannot reserve a second delivery operation",
        );

        let acknowledgement = database
            .store()
            .acknowledge_managed_secret_delivery(AcknowledgeManagedSecretDelivery::new(
                replay_request,
            )?)
            .await?;
        assert_eq!(acknowledgement.operation_id().as_uuid(), operation_id);
        let retry_acknowledgement = database
            .store()
            .acknowledge_managed_secret_delivery(AcknowledgeManagedSecretDelivery::new(
                execution.authenticated_delivery_request(121_200, operation_id, verifier)?,
            )?)
            .await?;
        assert_eq!(retry_acknowledgement, acknowledgement);
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(execution.authenticated_delivery_request(
                    121_300,
                    operation_id,
                    verifier,
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "acknowledged values cannot be resolved again",
        );

        let expiring_binding = BindingIdentity::fresh();
        let expiring = seed_current_execution(&database, vec![expiring_binding]).await?;
        seed_authority_state(&database, &expiring, false, true).await?;
        let expiring_operation = Uuid::new_v4();
        let expiring_verifier = digest(0xd4);
        database
            .store()
            .resolve_managed_secret_authority(expiring.delivery_request(
                121_000,
                expiring_operation,
                expiring_verifier,
            )?)
            .await?;
        assert_eq!(
            database
                .store()
                .acknowledge_managed_secret_delivery(AcknowledgeManagedSecretDelivery::new(
                    expiring.authenticated_delivery_request(
                        301_000,
                        expiring_operation,
                        expiring_verifier,
                    )?,
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "a response cannot be acknowledged after its exact authority deadline",
        );
        let expired_state: String = sqlx::query_scalar(
            "SELECT state FROM managed_secret_delivery_operations WHERE tenant_id = $1 AND operation_id = $2",
        )
        .bind(&expiring.tenant)
        .bind(expiring_operation)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(expired_state, "expired");

        let stored_plaintext_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'managed_secret_delivery_operations'
              AND column_name IN ('value', 'plaintext', 'credential', 'bearer')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(stored_plaintext_columns, 0);
        let restricted_parent_links: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM information_schema.referential_constraints
            WHERE constraint_schema = current_schema()
              AND constraint_name IN (
                  'managed_secret_delivery_operations_repository',
                  'managed_secret_delivery_operations_repository_run',
                  'managed_secret_delivery_operations_run_job',
                  'managed_secret_delivery_operations_job_attempt',
                  'managed_secret_delivery_operations_runner',
                  'managed_secret_delivery_operations_session'
              )
              AND delete_rule IN ('RESTRICT', 'NO ACTION')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(restricted_parent_links, 6);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn authenticated_delivery_requires_the_current_runner_machine() -> TestResult {
    run_with_database(|database| async move {
        let binding = BindingIdentity::fresh();
        let execution = seed_current_execution(&database, vec![binding]).await?;
        seed_authority_state(&database, &execution, false, true).await?;
        let operation_id = Uuid::new_v4();
        let verifier = digest(0xd6);

        let wrong_identity = ManagedSecretDeliveryMachine::new(
            format!("other-{}", execution.lease.runner_id().as_uuid().simple()),
            execution.machine.certificate_sha256(),
        )?;
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(
                    execution
                        .delivery_request(121_000, operation_id, verifier)?
                        .with_authenticated_machine(wrong_identity),
                )
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "fetch authority must be bound to the currently authenticated runner identity",
        );

        let wrong_certificate = ManagedSecretDeliveryMachine::new(
            execution.machine.external_identity().to_owned(),
            digest(0xd7),
        )?;
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(
                    execution
                        .delivery_request(121_000, operation_id, verifier)?
                        .with_authenticated_machine(wrong_certificate),
                )
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "fetch authority must be bound to the current unrevoked leaf certificate",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn delivery_operations_expire_when_the_current_attempt_leaves_live_states() -> TestResult {
    run_with_database(|database| async move {
        let binding = BindingIdentity::fresh();
        let execution = seed_current_execution(&database, vec![binding]).await?;
        seed_authority_state(&database, &execution, false, true).await?;
        let operation_id = Uuid::new_v4();
        let verifier = digest(0xd8);
        database
            .store()
            .resolve_managed_secret_authority(execution.delivery_request(
                121_000,
                operation_id,
                verifier,
            )?)
            .await?;

        sqlx::query(
            r"
            UPDATE job_attempts
            SET lifecycle = 'succeeded',
                lease_id = NULL,
                runner_id = NULL,
                lease_issued_at_ms = NULL,
                lease_expires_at_ms = NULL,
                runner_session_id = NULL,
                runner_session_epoch = NULL,
                runner_generation = NULL,
                runner_slot = NULL,
                changed_at_ms = $2
            WHERE id = $1
            ",
        )
        .bind(execution.lease.attempt_id().as_uuid())
        .bind(execution.time(121_100))
        .execute(database.pool())
        .await?;

        let expired_state: String = sqlx::query_scalar(
            "SELECT state FROM managed_secret_delivery_operations WHERE tenant_id = $1 AND operation_id = $2",
        )
        .bind(&execution.tenant)
        .bind(operation_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(expired_state, "expired");
        assert_eq!(
            database
                .store()
                .acknowledge_managed_secret_delivery(AcknowledgeManagedSecretDelivery::new(
                    execution.authenticated_delivery_request(121_200, operation_id, verifier)?,
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "terminal attempt transitions must close the pending delivery row",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn delivery_operations_expire_when_the_runner_session_disconnects() -> TestResult {
    run_with_database(|database| async move {
        let binding = BindingIdentity::fresh();
        let execution = seed_current_execution(&database, vec![binding]).await?;
        seed_authority_state(&database, &execution, false, true).await?;
        let operation_id = Uuid::new_v4();
        let verifier = digest(0xd9);
        database
            .store()
            .resolve_managed_secret_authority(execution.delivery_request(
                121_000,
                operation_id,
                verifier,
            )?)
            .await?;

        sqlx::query(
            r"
            UPDATE runner_sessions
            SET disconnected_at_ms = $2
            WHERE id = $1
            ",
        )
        .bind(execution.session.session_id().as_uuid())
        .bind(execution.time(121_100))
        .execute(database.pool())
        .await?;

        let expired_state: String = sqlx::query_scalar(
            "SELECT state FROM managed_secret_delivery_operations WHERE tenant_id = $1 AND operation_id = $2",
        )
        .bind(&execution.tenant)
        .bind(operation_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(expired_state, "expired");
        assert_eq!(
            database
                .store()
                .acknowledge_managed_secret_delivery(AcknowledgeManagedSecretDelivery::new(
                    execution.authenticated_delivery_request(121_200, operation_id, verifier)?,
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "session disconnects must close the pending delivery row",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn protected_environment_approval_aba_remains_closed_and_non_enumerating() -> TestResult {
    run_with_database(|database| async move {
        let binding = BindingIdentity::fresh();
        let execution = seed_current_execution(&database, vec![binding]).await?;
        let (_, environment_id, _) =
            seed_authority_state(&database, &execution, true, true).await?;
        let environment_id = environment_id.ok_or("fixture environment missing")?;
        let operation_id = Uuid::new_v4();
        let verifier = digest(0xe1);
        database
            .store()
            .resolve_managed_secret_authority(execution.delivery_request(
                121_000,
                operation_id,
                verifier,
            )?)
            .await?;

        sqlx::query(
            r"
            UPDATE repository_environments
            SET required_approvals = 2, revision = 2, updated_at_ms = $4
            WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
            ",
        )
        .bind(&execution.tenant)
        .bind(execution.repository_id.as_uuid())
        .bind(environment_id)
        .bind(execution.time(121_100))
        .execute(database.pool())
        .await?;
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(execution.delivery_request(
                    121_200,
                    operation_id,
                    verifier,
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
        );
        sqlx::query(
            r"
            UPDATE repository_environments
            SET required_approvals = 1, revision = 3, updated_at_ms = $4
            WHERE tenant_id = $1 AND repository_id = $2 AND id = $3
            ",
        )
        .bind(&execution.tenant)
        .bind(execution.repository_id.as_uuid())
        .bind(environment_id)
        .bind(execution.time(121_300))
        .execute(database.pool())
        .await?;
        assert_eq!(
            database
                .store()
                .resolve_managed_secret_authority(execution.delivery_request(
                    121_400,
                    operation_id,
                    verifier,
                )?)
                .await,
            Err(ManagedSecretAuthorityStoreError::Unauthorized),
            "matching mutable settings cannot prove approval freshness after ABA",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn in_flight_grant_insert_is_linearized_before_exact_cardinality() -> TestResult {
    run_with_database(|database| async move {
        let binding = BindingIdentity::fresh();
        let execution = seed_current_execution(&database, vec![binding]).await?;
        let (actor, environment_id, _) =
            seed_authority_state(&database, &execution, false, true).await?;
        let concurrent_binding = BindingIdentity::fresh();
        seed_repository_secret(
            database.pool(),
            execution.repository_id,
            &actor,
            concurrent_binding,
            1,
        )
        .await?;
        let mut transaction = database.pool().begin().await?;
        let blocking_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *transaction)
            .await?;
        insert_workload_grant_in_transaction(
            &mut transaction,
            &execution,
            concurrent_binding,
            environment_id,
            None,
            91,
        )
        .await?;

        // Exercise the actual value-bearing reservation path. A request without
        // an operation/bearer is rejected before it reaches the exact execution
        // locks and therefore cannot prove the insert/authority linearization.
        let request = execution.delivery_request(121_000, Uuid::new_v4(), digest(0xd5))?;
        let resolver_database = Arc::clone(&database);
        let resolver = tokio::spawn(async move {
            resolver_database
                .store()
                .resolve_managed_secret_authority(request)
                .await
        });
        wait_for_backend_blocked_by(database.pool(), blocking_backend_pid).await?;
        transaction.commit().await?;
        let result = tokio::time::timeout(Duration::from_secs(5), resolver).await??;
        assert_eq!(result, Err(ManagedSecretAuthorityStoreError::Unauthorized));
        Ok(())
    })
    .await
}

async fn wait_for_backend_blocked_by(pool: &PgPool, blocking_backend_pid: i32) -> TestResult<i32> {
    for _ in 0..500 {
        let waiting_backend_pid: Option<i32> = sqlx::query_scalar(
            r"
            SELECT pid
            FROM pg_stat_activity
            WHERE pid <> $1
              AND $1 = ANY(pg_blocking_pids(pid))
            ORDER BY pid
            LIMIT 1
            ",
        )
        .bind(blocking_backend_pid)
        .fetch_optional(pool)
        .await?;
        if let Some(waiting_backend_pid) = waiting_backend_pid {
            return Ok(waiting_backend_pid);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("authority operation did not block behind the in-flight mutation".into())
}
