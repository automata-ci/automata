use crate::github_manifest_fixture;

use std::{collections::BTreeMap, time::Duration};

use automata_ci_control::runner_control::repository::RunnerSessionRepository as _;
use automata_ci_core::{
    Architecture, ContextValue, FencingToken, JobAuthorityProfile, JobContentReference,
    JobExecutionContext, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobRuntimeContext,
    JobSource, Lease, LeaseId, OperatingSystem, RunId, RunValueTemplates, RunnerCapabilities,
    RunnerId, RunnerPlatform, RunnerRequirements, RunnerSessionId, RuntimeBoolean, SemanticStep,
    Sha256Digest, ShellTemplate, StepId, StepIr, StrategyContext, UnixMillis, ValueTemplate,
    WorkflowId, WorkflowJobKey,
};
use automata_ci_key_management::{ENVELOPE_SCHEMA_V1, EncryptedEnvelope, KeyId, WrappedDataKey};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BeginGithubRuntimeAuthorityMint,
    BeginGithubRuntimeAuthorityMintOutcome, BindLogicalActivationPreparation,
    ClaimGithubRuntimeAuthorityMint, ClaimGithubRuntimeAuthorityRevocation,
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ClaimProviderDelivery, ClaimedLogicalInstanceMaterialization, ClaimedLogicalJobActivation,
    ClaimedProviderDelivery, CommitGithubRuntimeAuthority, CommitLogicalInstanceMaterialization,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, EnsureGithubServerServiceAuthority,
    GithubCheckHeadSha, GithubCheckName, GithubJobRuntimeAuthorityExecution,
    GithubJobRuntimeAuthorityRepository as _, GithubJobRuntimeAuthorityResolution,
    GithubJobRuntimeAuthorityStoreError, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryId, GithubRepositoryName,
    GithubRuntimeAuthorityActivationSelectionTail, GithubRuntimeAuthorityEnvelopeMetadata,
    GithubRuntimeAuthorityIdentity, GithubRuntimeAuthorityMaterializationSelectionTail,
    GithubRuntimeAuthorityPreparationSelectionTail, GithubRuntimeAuthorityRepository as _,
    GithubRuntimeAuthorityState, GithubRuntimeAuthorityWorkerId, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    InspectGithubRuntimeAuthority, JobEnvironmentActivationEvidence, JobEventTrust, JobIrMetadata,
    JobSourceKind, LogicalActivationObject, LogicalActivationPreparationStore as _,
    LogicalActivationPreparationTarget, LogicalActivationRepository as _,
    LogicalActivationWorkerId, LogicalInstanceMaterializationSelectionOutcome,
    LogicalInstanceMaterializationTarget, LogicalJobOrchestrationSelectionOutcome,
    LogicalMaterializationRepository as _, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    LogicalWorkSelectionRepository as _, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind, ObjectKey,
    OpenRunnerSession, ProtectedGithubRuntimeAuthority, ProviderConnectionId,
    ProviderDeliveryClaimOwnerId, ProviderDeliveryIdentity, ProviderDeliveryRepository as _,
    ProviderDeliveryWorkflowInventory, ProviderDeliveryWorkflowInventoryEntry,
    ProviderDeliveryWorkflowSourceState, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    PublishLogicalJobActivation, RegisterProviderDeliveryWorkflowInventory,
    RenewLogicalActivationPreparation, RenewLogicalInstanceMaterialization,
    RenewLogicalJobActivation, ReusableSecretPermission,
    RevalidateGithubRuntimeAuthorityRevocation, RoutingDocument, RunnerGeneration,
    RunnerProtocolVersion, RunnerSessionFence, StableRunnerSlot, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowPlanRepository as _, WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::support::{TestClock, TestDatabase, TestResult, run_with_database};

const WORKFLOW_PATH: &str = ".ci/workflows/ci.yml";

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn admission_object(key: String, byte: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        digest(byte),
        ObjectKey::new(key).expect("object key"),
        512,
        media_type,
    )
    .expect("admission object")
}

struct LogicalFixture {
    tenant: String,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    logical_job_id: LogicalWorkflowJobId,
}

struct PreparedInstance {
    activated: ActivatedLogicalInstanceDescriptor,
    envelope: JobIrEnvelope,
    encoded: Vec<u8>,
    runtime_context: JobRuntimeContext,
    runtime_encoded: Vec<u8>,
}

fn logical_fixture(
    namespace: u128,
    visibility: ProviderRepositoryVisibility,
    database_epoch: UnixMillis,
) -> LogicalFixture {
    let tenant = format!("job-authority-{}", Uuid::new_v4().simple());
    let tenant_scope = TenantScope::from_authenticated_tenant_id(&tenant).expect("tenant scope");
    let manifest = manifest(tenant_scope.clone(), namespace, visibility);
    let workflow_id = automata_ci_core::WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("invocation");
    let logical_job_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("logical job");
    let logical_job = AdmittedLogicalWorkflowJob::new(
        logical_job_id,
        WorkflowJobKey::new("verify").expect("logical key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("logical job");
    let command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!("job-authority-{namespace}"))
            .expect("idempotency"),
        digest(0x40),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            manifest.github_repository_id().get().to_string(),
            "example",
            "project",
        )
        .expect("repository"),
        workflow_id,
        WORKFLOW_PATH,
        "CI",
        "refs/heads/main",
        snapshot_id,
        admission_object(
            format!("job-authority/{namespace}/source"),
            0x11,
            "application/yaml",
        ),
        admission_object(
            format!("job-authority/{namespace}/plan"),
            0x12,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(
            format!("job-authority/{namespace}/event"),
            0x13,
            "application/json",
        ),
        vec![0x14; 20],
        vec![logical_job],
        database_epoch,
    )
    .base_context(admission_object(
        format!("job-authority/{namespace}/base-context"),
        0x15,
        "application/vnd.automata.job-runtime-context.protobuf",
    ))
    .build()
    .expect("logical admission");
    LogicalFixture {
        tenant,
        manifest,
        command,
        logical_job_id,
    }
}

fn manifest(
    tenant: TenantScope,
    namespace: u128,
    visibility: ProviderRepositoryVisibility,
) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    GithubProviderManifest::new(
        tenant,
        ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 10)).expect("connection"),
        ProviderInstallationId::new(u64::try_from(namespace + 11).expect("installation"))
            .expect("installation"),
        ProviderRepositoryId::new(u64::try_from(namespace + 12).expect("repository ID"))
            .expect("repository ID"),
        GithubRepositoryName::new("example/project").expect("repository name"),
        visibility,
        GithubServerServiceAppId::new(u64::try_from(namespace + 13).expect("App ID"))
            .expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        digest(0x71),
        GithubServerServiceRevision::new(1).expect("App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(digest(0x72))
            .expect("verifier fingerprint"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
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

fn rotated_credential_free_manifest(prior: &GithubProviderManifest) -> GithubProviderManifest {
    GithubProviderManifest::new(
        prior.tenant().clone(),
        prior.connection_id(),
        prior.installation_id(),
        prior.github_repository_id(),
        prior.github_repository_name().clone(),
        prior.repository_visibility(),
        prior.github_app_id(),
        prior.app_client_id().clone(),
        prior.jwt_issuer(),
        prior.app_key_spki_sha256(),
        prior.app_configuration_revision(),
        prior.webhook_verifier_fingerprint(),
        prior.webhook_verifier_revision(),
        GithubServerServiceRevision::new(prior.policy_revision().get() + 1)
            .expect("policy revision"),
        JobAuthorityProfile::CredentialFree,
        prior.runner_policy().clone(),
        prior.runtime_policy_revision(),
        prior.runtime_policy_digest(),
        prior.check_name().clone(),
        prior.origins(),
        prior.limits(),
        GithubProviderManifestRevision::new(prior.revision().get() + 1).expect("manifest revision"),
    )
}

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Job authority test', 1, 1)",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    Ok(UnixMillis::new(now))
}

async fn install_database_test_clock(
    database: &TestDatabase,
    now_ms: i64,
) -> TestResult<TestClock> {
    TestClock::freeze(database.pool(), now_ms).await
}

async fn set_database_test_clock(clock: &TestClock, now_ms: i64) -> TestResult {
    clock.set(now_ms).await?;
    if clock.now().await? != now_ms {
        return Err("job-runtime-authority test database clock is inconsistent".into());
    }
    Ok(())
}

fn retime_logical_admission(
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

#[allow(clippy::too_many_lines)] // Keep the canonical signed-admission transaction visible end to end.
async fn admit_signed_workflow(
    database: &TestDatabase,
    fixture: &mut LogicalFixture,
    database_epoch: UnixMillis,
) -> TestResult {
    let tenant = TenantScope::from_authenticated_tenant_id(&fixture.tenant)?;
    let manifest = &fixture.manifest;
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                database_epoch,
            ),
        )
        .await
        .map_err(|error| format!("repository bootstrap failed: {error:?}"))?;
    let checks = service_authority(
        manifest,
        namespace_id(manifest, 1),
        GithubServerServiceScope::ChecksWrite,
        digest(0x73),
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            checks,
            database_epoch,
        )?)
        .await
        .map_err(|error| format!("checks authority bootstrap failed: {error:?}"))?;
    if manifest.repository_visibility() == ProviderRepositoryVisibility::Private {
        let source = service_authority(
            manifest,
            namespace_id(manifest, 2),
            GithubServerServiceScope::PrivateRepositorySourceRead,
            digest(0x74),
        )?;
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                source,
                database_epoch,
            )?)
            .await
            .map_err(|error| format!("private authority bootstrap failed: {error:?}"))?;
    }
    let identity = ProviderDeliveryIdentity::new(
        tenant,
        "github",
        manifest.connection_id(),
        manifest.installation_id(),
        ProviderRepositoryCoordinates::new(
            manifest.github_repository_id(),
            manifest.repository_visibility(),
            manifest.github_repository_name().as_str(),
        )?,
        fixture.command.idempotency().key(),
    )?;
    let head_sha: [u8; 20] = fixture
        .command
        .head_sha()
        .try_into()
        .map_err(|_| "head SHA")?;
    let delivery_observed_at = database_now(database).await?;
    let accepted = database
        .store()
        .accept_manifest_pinned_github_delivery(AcceptManifestPinnedGithubDelivery::new(
            AcceptProviderDelivery::new(
                identity,
                fixture.command.request_digest(),
                crate::support::authenticated_github_event_object(fixture.command.event())?,
                crate::support::provider_delivery_event_envelope(0x8a),
                delivery_observed_at,
            )?,
            ProviderRepositoryOwnerId::new(404)?,
            ProviderRepositoryOwnerId::new(404)?,
            automata_ci_store::GithubAuthenticatedEvent::new(
                automata_ci_store::GithubAuthenticatedEventKind::Push,
                "refs/heads/main",
            )?,
            GithubCheckHeadSha::new(head_sha)?,
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
        )?)
        .await
        .map_err(|error| format!("delivery acceptance failed: {error:?}"))?;
    let delivery_claim_observed_at = database_now(database).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4())?,
            delivery_claim_observed_at,
            UnixMillis::new(
                delivery_claim_observed_at
                    .get()
                    .checked_add(60_000)
                    .ok_or("database time")?,
            ),
        )?)
        .await
        .map_err(|error| format!("delivery claim failed: {error:?}"))?
        .ok_or("delivery was not claimable")?;
    if claimed.claim().delivery_id() != accepted.delivery_id() {
        return Err("foreign delivery claimed".into());
    }
    register_workflow_inventory(database, fixture, &claimed).await?;
    let authenticated = AuthenticatedGithubDeliveryClaim::new(
        claimed.claim(),
        claimed.attempt(),
        claimed.claimed_at(),
        claimed.expires_at(),
    )?;
    fixture.command = retime_logical_admission(&fixture.command, claimed.claimed_at())?;
    database
        .store()
        .admit_authenticated_github_delivery(
            fixture.command.clone(),
            authenticated,
            fixture.command.admitted_at(),
        )
        .await
        .map_err(|error| format!("authenticated admission failed: {error:?}"))?;
    Ok(())
}

async fn register_workflow_inventory(
    database: &TestDatabase,
    fixture: &LogicalFixture,
    claimed: &ClaimedProviderDelivery,
) -> TestResult {
    let inventory = ProviderDeliveryWorkflowInventory::new(
        fixture.manifest.digest(),
        "1414141414141414141414141414141414141414",
        digest(0x90),
        vec![ProviderDeliveryWorkflowInventoryEntry::new(
            WORKFLOW_PATH,
            ProviderDeliveryWorkflowSourceState::Ready(fixture.command.source().digest()),
        )?],
    )?;
    database
        .store()
        .register_provider_delivery_workflow_inventory(
            RegisterProviderDeliveryWorkflowInventory::new(
                claimed.claim(),
                inventory,
                claimed.claimed_at(),
            )?,
        )
        .await?;
    Ok(())
}

fn namespace_id(manifest: &GithubProviderManifest, suffix: u128) -> u128 {
    manifest.connection_id().as_uuid().as_u128() + 100 + suffix
}

fn service_authority(
    manifest: &GithubProviderManifest,
    id: u128,
    scope: GithubServerServiceScope,
    configuration_fingerprint: Sha256Digest,
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    Ok(GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(id))?,
        manifest.repository_id(),
        manifest.connection_id(),
        manifest.installation_id(),
        manifest.github_app_id(),
        manifest.github_repository_id(),
        manifest.github_repository_name().clone(),
        scope,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
        configuration_fingerprint,
    )?)
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
    let bound_at = database_now(database).await?;
    let prepared = database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            preparation.descriptor().clone(),
            preparation.claim().clone(),
            preparation.descriptor().base_context().clone(),
            admission_object(
                format!("{}/needs-context", fixture.tenant),
                0x52,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            bound_at,
        )?)
        .await?;
    match select_orchestration(database, &target).await? {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
            if claimed.claim().input_digest() != prepared.input_digest() {
                return Err("selected activation carried foreign prepared evidence".into());
            }
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
    let observed_at = database_now(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
            LogicalActivationWorkerId::from_uuid(Uuid::new_v4())?,
            observed_at,
            60_000,
        )?)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected orchestration selection, got {outcome:?}").into()),
    };
    if selected.target() != expected_target {
        return Err("orchestration selector returned a foreign target".into());
    }
    let consumed = database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected.clone(),
        ))
        .await?;
    match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => {
            database
                .store()
                .renew_logical_activation_preparation(RenewLogicalActivationPreparation::new(
                    claimed.claim().clone(),
                    120_000,
                )?)
                .await?;
        }
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
            database
                .store()
                .renew_logical_job_activation(RenewLogicalJobActivation::new(
                    claimed.claim().clone(),
                    120_000,
                )?)
                .await?;
        }
    }
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
    expected_target: &LogicalInstanceMaterializationTarget,
) -> TestResult<ClaimedLogicalInstanceMaterialization> {
    let observed_at = database_now(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_instance_materialization(ClaimNextLogicalInstanceMaterialization::new(
            LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
            LogicalMaterializationWorkerId::from_uuid(Uuid::new_v4())?,
            observed_at,
            60_000,
        )?)
        .await?
    {
        LogicalInstanceMaterializationSelectionOutcome::Selected(selected) => selected,
        outcome => {
            return Err(format!("expected materialization selection, got {outcome:?}").into());
        }
    };
    if selected.target() != expected_target {
        return Err("materialization selector returned a foreign target".into());
    }
    let consumed = database
        .store()
        .consume_selected_logical_instance_materialization(
            ConsumeSelectedLogicalInstanceMaterialization::new(selected.clone()),
        )
        .await?;
    database
        .store()
        .renew_logical_instance_materialization(RenewLogicalInstanceMaterialization::new(
            consumed.authority().claim().clone(),
            120_000,
        )?)
        .await?;
    Ok(database
        .store()
        .consume_selected_logical_instance_materialization(
            ConsumeSelectedLogicalInstanceMaterialization::new(selected),
        )
        .await?
        .authority()
        .clone())
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

fn prepare_instance(
    fixture: &LogicalFixture,
    claimed: &ClaimedLogicalJobActivation,
) -> PreparedInstance {
    let matrix_digest = digest(0x61);
    let identity =
        JobInstanceIdentity::new("verify", 0, 1, matrix_digest).expect("instance identity");
    let empty = ContextValue::object(BTreeMap::new()).expect("empty context");
    let runtime_context = JobRuntimeContext::new(
        empty.clone(),
        empty.clone(),
        empty,
        StrategyContext::new(false, 0, 1, 1).expect("strategy"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("runtime context");
    let runtime_encoded = serde_json::to_vec(&runtime_context).expect("runtime encoding");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes(Sha256::digest(&runtime_encoded).into()),
        ObjectKey::new(format!("{}/runtime-context", fixture.tenant)).expect("runtime key"),
        u64::try_from(runtime_encoded.len()).expect("runtime size"),
    )
    .expect("runtime descriptor");
    let workspace = "/srv/work/project";
    let step = StepIr::new_literal_name(
        StepId::new("run").expect("step ID"),
        "Run",
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("true").expect("command"),
            ShellTemplate::default_shell(),
        )),
    )
    .expect("step");
    let job = JobIr::new(
        concrete_job_id(
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.logical_job_id,
            matrix_digest,
        ),
        fixture.command.run_id(),
        "Verify",
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
            WORKFLOW_PATH,
            "push",
        ),
        job_execution,
        job,
    );
    envelope.validate().expect("current JobIR");
    let encoded = serde_json::to_vec(&envelope).expect("JobIR encoding");
    let activated = ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        workspace,
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new(format!("{}/job-ir", fixture.tenant)).expect("JobIR key"),
            u64::try_from(encoded.len()).expect("JobIR size"),
        )
        .expect("JobIR descriptor"),
        runtime,
        JobEnvironmentActivationEvidence::new(
            None,
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        ),
    )
    .expect("activated instance");
    PreparedInstance {
        activated,
        envelope,
        encoded,
        runtime_context,
        runtime_encoded,
    }
}

#[allow(clippy::too_many_lines)] // The fixture mirrors the complete immutable execution graph.
async fn seed_execution(
    database: &TestDatabase,
    namespace: u128,
    visibility: ProviderRepositoryVisibility,
) -> TestResult<(GithubJobRuntimeAuthorityExecution, GithubProviderManifest)> {
    let database_epoch = database_now(database).await?;
    let mut fixture = logical_fixture(namespace, visibility, database_epoch);
    seed_tenant(database, &fixture.tenant).await?;
    admit_signed_workflow(database, &mut fixture, database_epoch).await?;
    let claimed = claim_activation(database, &fixture).await?;
    let prepared = prepare_instance(&fixture, &claimed);
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            claimed.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            claimed.claim().claimed_at(),
        )?)
        .await?;
    let target = LogicalInstanceMaterializationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
        prepared.activated.id(),
    )?;
    let materialization = select_materialization(database, &target).await?;
    let materialized_at = database_now(database).await?;
    let materialized = database
        .store()
        .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
            &materialization,
            &prepared.encoded,
            &prepared.envelope,
            &prepared.runtime_encoded,
            &prepared.runtime_context,
            materialized_at,
        )?)
        .await?;
    let runner_epoch = database_now(database).await?;
    let runner_id = RunnerId::from_uuid(Uuid::from_u128(namespace + 300));
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    );
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots, status,
            desired_state, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, $3, $4::jsonb, 1, 'online', 'active', $5, $5)
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(&fixture.tenant)
    .bind(format!("runner-{namespace}"))
    .bind(serde_json::to_value(&capabilities)?)
    .bind(runner_epoch.get())
    .execute(database.pool())
    .await?;
    let session = database
        .store()
        .open_session(OpenRunnerSession::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(1)?,
            RunnerProtocolVersion::new(1)?,
            automata_ci_core::JobIrVersion::current(),
            RoutingDocument::new(serde_json::to_string(&capabilities)?)?,
            runner_epoch,
        ))
        .await?;
    let lease_epoch = database_now(database).await?;
    let lease_expires_at = lease_epoch
        .get()
        .checked_add(300_000)
        .ok_or("database time")?;
    let lease_id = LeaseId::new();
    let fence = FencingToken::new(7)?;
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
    .bind(materialized.attempt_id().as_uuid())
    .bind(i64::try_from(fence.get())?)
    .bind(lease_id.as_uuid())
    .bind(runner_id.as_uuid())
    .bind(session.fence().session_id().as_uuid())
    .bind(i64::try_from(session.fence().session_epoch().get())?)
    .bind(i64::try_from(session.fence().runner_generation().get())?)
    .bind(lease_epoch.get())
    .bind(lease_expires_at)
    .execute(database.pool())
    .await?;
    if changed.rows_affected() != 1 {
        return Err("initial attempt was not queued".into());
    }
    let metadata = database
        .store()
        .get_job_ir_metadata(materialized.job_id())
        .await?;
    let lease = Lease::new(
        lease_id,
        materialized.attempt_id(),
        runner_id,
        fence,
        lease_epoch,
        UnixMillis::new(lease_expires_at),
    )?;
    let execution = GithubJobRuntimeAuthorityExecution::new(
        fixture.command.workflow_id(),
        fixture.manifest.github_repository_name().clone(),
        JobAuthorityProfile::Standard,
        metadata.digest(),
        lease,
        session.fence(),
        StableRunnerSlot::new(1)?,
        metadata,
    )?;
    Ok((execution, fixture.manifest))
}

fn exact_standard_identity(
    resolution: GithubJobRuntimeAuthorityResolution,
    execution: &GithubJobRuntimeAuthorityExecution,
    manifest: &GithubProviderManifest,
) -> TestResult<GithubRuntimeAuthorityIdentity> {
    let GithubJobRuntimeAuthorityResolution::Standard(evidence) = resolution else {
        return Err("Standard execution resolved without repository authority".into());
    };
    assert_eq!(evidence.workflow_id(), execution.workflow_id());
    assert_eq!(evidence.job_ir(), execution.job_ir());
    let identity = evidence.identity();
    assert_eq!(identity.repository_id(), manifest.repository_id());
    assert_eq!(identity.provider_connection_id(), manifest.connection_id());
    assert_eq!(
        identity.provider_installation_id(),
        manifest.installation_id()
    );
    assert_eq!(
        identity.github_repository_id().get(),
        manifest.github_repository_id().get()
    );
    assert_eq!(
        identity.github_repository_name(),
        manifest.github_repository_name()
    );
    assert_eq!(identity.namespace().as_str(), "github.repository");
    assert_eq!(identity.policy_digest(), execution.job_ir().digest());
    assert_eq!(identity.github_app_id(), manifest.github_app_id());
    assert_eq!(identity.github_app_client_id(), manifest.app_client_id());
    assert_eq!(identity.github_app_jwt_issuer_kind(), manifest.jwt_issuer());
    assert_eq!(
        identity.github_app_jwt_issuer_value(),
        manifest.app_client_id().as_str()
    );
    assert_eq!(
        identity.app_key_spki_sha256(),
        manifest.app_key_spki_sha256()
    );
    assert_eq!(identity.configuration_fingerprint(), digest(0x73));
    let preparation_tail = identity.preparation_selection_tail();
    let activation_tail = identity.activation_selection_tail();
    let materialization_tail = identity.materialization_selection_tail();
    assert_eq!(preparation_tail.generation().get(), 2);
    assert_eq!(activation_tail.generation().get(), 2);
    assert_eq!(materialization_tail.generation().get(), 2);
    assert_ne!(
        preparation_tail.selection_id(),
        activation_tail.selection_id()
    );
    assert_ne!(
        activation_tail.selection_id(),
        materialization_tail.selection_id()
    );
    assert!(preparation_tail.expires_at() > preparation_tail.claimed_at());
    assert!(activation_tail.expires_at() > activation_tail.claimed_at());
    assert!(materialization_tail.expires_at() > materialization_tail.claimed_at());
    assert_eq!(identity.lease_id(), execution.lease().lease_id());
    assert_eq!(identity.key().attempt_id(), execution.lease().attempt_id());
    assert_eq!(
        identity.key().fencing_token(),
        execution.lease().fencing_token()
    );
    assert_eq!(
        identity.runner_session_id(),
        execution.session().session_id()
    );
    assert_eq!(identity.job_ir_digest(), execution.job_ir().digest());
    Ok(identity.clone())
}

fn protected_runtime_authority(
    identity: GithubRuntimeAuthorityIdentity,
) -> TestResult<ProtectedGithubRuntimeAuthority> {
    let plaintext_size_bytes = 32;
    let metadata = GithubRuntimeAuthorityEnvelopeMetadata::new(
        identity,
        None,
        plaintext_size_bytes,
        digest(0xb1),
    )?;
    let envelope = EncryptedEnvelope::from_parts(
        ENVELOPE_SCHEMA_V1,
        WrappedDataKey::new(KeyId::new("runtime-authority-test-v1")?, vec![0xa5; 32])?,
        [0x2a; 12],
        vec![0xcc; usize::try_from(plaintext_size_bytes)? + 16],
    )?;
    Ok(ProtectedGithubRuntimeAuthority::new(metadata, envelope)?)
}

#[allow(clippy::too_many_arguments)]
fn execution_variant(
    base: &GithubJobRuntimeAuthorityExecution,
    workflow_id: WorkflowId,
    repository_name: GithubRepositoryName,
    profile: JobAuthorityProfile,
    lease: Lease,
    session: RunnerSessionFence,
    job_ir: JobIrMetadata,
) -> TestResult<GithubJobRuntimeAuthorityExecution> {
    Ok(GithubJobRuntimeAuthorityExecution::new(
        workflow_id,
        repository_name,
        profile,
        job_ir.digest(),
        lease,
        session,
        base.slot(),
        job_ir,
    )?)
}

#[allow(clippy::needless_pass_by_value)] // Consume the one-shot async outcome at the assertion boundary.
fn assert_unauthorized<T>(
    result: Result<T, GithubJobRuntimeAuthorityStoreError>,
    substitution: &str,
) {
    assert!(
        matches!(
            result,
            Err(GithubJobRuntimeAuthorityStoreError::Unauthorized)
        ),
        "{substitution} must fail closed"
    );
}

async fn assert_phase_selection_origins_are_immutable(
    database: &TestDatabase,
    job_id: JobId,
) -> TestResult<()> {
    for (label, statement) in [
        (
            "missing preparation origin",
            r"
            UPDATE logical_workflow_activation_preparation_claims AS preparation
            SET origin_selection_id = NULL
            FROM logical_workflow_concrete_jobs AS concrete
            WHERE concrete.job_id = $1
              AND preparation.run_id = concrete.run_id
              AND preparation.invocation_id = concrete.invocation_id
              AND preparation.logical_job_id = concrete.logical_job_id
            ",
        ),
        (
            "swapped preparation origin",
            r"
            UPDATE logical_workflow_activation_preparation_claims AS preparation
            SET origin_selection_id = logical_job.activation_origin_selection_id
            FROM logical_workflow_concrete_jobs AS concrete
            JOIN logical_workflow_jobs AS logical_job
              ON logical_job.run_id = concrete.run_id
             AND logical_job.invocation_id = concrete.invocation_id
             AND logical_job.id = concrete.logical_job_id
            WHERE concrete.job_id = $1
              AND preparation.run_id = concrete.run_id
              AND preparation.invocation_id = concrete.invocation_id
              AND preparation.logical_job_id = concrete.logical_job_id
            ",
        ),
        (
            "missing activation origin",
            r"
            UPDATE logical_workflow_jobs AS logical_job
            SET activation_origin_selection_id = NULL
            FROM logical_workflow_concrete_jobs AS concrete
            WHERE concrete.job_id = $1
              AND logical_job.run_id = concrete.run_id
              AND logical_job.invocation_id = concrete.invocation_id
              AND logical_job.id = concrete.logical_job_id
            ",
        ),
        (
            "swapped activation origin",
            r"
            UPDATE logical_workflow_jobs AS logical_job
            SET activation_origin_selection_id = preparation.origin_selection_id
            FROM logical_workflow_concrete_jobs AS concrete
            JOIN logical_workflow_activation_preparation_claims AS preparation
              ON preparation.run_id = concrete.run_id
             AND preparation.invocation_id = concrete.invocation_id
             AND preparation.logical_job_id = concrete.logical_job_id
            WHERE concrete.job_id = $1
              AND logical_job.run_id = concrete.run_id
              AND logical_job.invocation_id = concrete.invocation_id
              AND logical_job.id = concrete.logical_job_id
            ",
        ),
        (
            "missing materialization origin",
            r"
            UPDATE logical_workflow_materialization_claims
            SET origin_selection_id = NULL
            WHERE expected_job_id = $1
            ",
        ),
        (
            "swapped materialization origin",
            r"
            UPDATE logical_workflow_materialization_claims AS materialization
            SET origin_selection_id = logical_job.activation_origin_selection_id
            FROM logical_workflow_concrete_jobs AS concrete
            JOIN logical_workflow_jobs AS logical_job
              ON logical_job.run_id = concrete.run_id
             AND logical_job.invocation_id = concrete.invocation_id
             AND logical_job.id = concrete.logical_job_id
            WHERE concrete.job_id = $1
              AND materialization.instance_id = concrete.instance_id
            ",
        ),
    ] {
        let error = sqlx::query(statement)
            .bind(job_id.as_uuid())
            .execute(database.pool())
            .await
            .expect_err(label);
        let code = error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code);
        assert_eq!(code.as_deref(), Some("23514"), "{label} must fail closed");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum IdentitySubstitution {
    ProviderConnection,
    ProviderInstallation,
    GithubAppId,
    GithubAppClientId,
    GithubAppJwtIssuerKind,
    GithubRepository,
    AppKeySpki,
    ConfigurationFingerprint,
    PolicyDigest,
    PreparationOrigin,
    PreparationTail,
    ActivationOrigin,
    ActivationTail,
    MaterializationOrigin,
    MaterializationTail,
}

struct SubstitutedProviderIdentity {
    connection_id: ProviderConnectionId,
    installation_id: ProviderInstallationId,
    app_id: GithubServerServiceAppId,
    app_client_id: GithubServerServiceAppClientId,
    app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
    repository_id: GithubRepositoryId,
    policy_digest: Sha256Digest,
    app_key_spki_sha256: Sha256Digest,
    configuration_fingerprint: Sha256Digest,
}

fn substituted_provider_identity(
    base: &GithubRuntimeAuthorityIdentity,
    substitution: IdentitySubstitution,
) -> TestResult<SubstitutedProviderIdentity> {
    Ok(SubstitutedProviderIdentity {
        connection_id: if matches!(substitution, IdentitySubstitution::ProviderConnection) {
            ProviderConnectionId::from_uuid(Uuid::new_v4())?
        } else {
            base.provider_connection_id()
        },
        installation_id: if matches!(substitution, IdentitySubstitution::ProviderInstallation) {
            ProviderInstallationId::new(base.provider_installation_id().get() + 1)?
        } else {
            base.provider_installation_id()
        },
        app_id: if matches!(substitution, IdentitySubstitution::GithubAppId) {
            GithubServerServiceAppId::new(base.github_app_id().get() + 1)?
        } else {
            base.github_app_id()
        },
        app_client_id: if matches!(substitution, IdentitySubstitution::GithubAppClientId) {
            GithubServerServiceAppClientId::new("Iv1.rotated-runtime-authority")?
        } else {
            base.github_app_client_id().clone()
        },
        app_jwt_issuer_kind: if matches!(substitution, IdentitySubstitution::GithubAppJwtIssuerKind)
        {
            GithubServerServiceJwtIssuer::AppId
        } else {
            base.github_app_jwt_issuer_kind()
        },
        repository_id: if matches!(substitution, IdentitySubstitution::GithubRepository) {
            GithubRepositoryId::new(base.github_repository_id().get() + 1)?
        } else {
            base.github_repository_id()
        },
        policy_digest: if matches!(substitution, IdentitySubstitution::PolicyDigest) {
            digest(0x93)
        } else {
            base.policy_digest()
        },
        app_key_spki_sha256: if matches!(substitution, IdentitySubstitution::AppKeySpki) {
            digest(0x91)
        } else {
            base.app_key_spki_sha256()
        },
        configuration_fingerprint: if matches!(
            substitution,
            IdentitySubstitution::ConfigurationFingerprint
        ) {
            digest(0x92)
        } else {
            base.configuration_fingerprint()
        },
    })
}

struct SubstitutedSelectionTails {
    preparation: GithubRuntimeAuthorityPreparationSelectionTail,
    activation: GithubRuntimeAuthorityActivationSelectionTail,
    materialization: GithubRuntimeAuthorityMaterializationSelectionTail,
}

fn substituted_selection_tails(
    base: &GithubRuntimeAuthorityIdentity,
    substitution: IdentitySubstitution,
) -> TestResult<SubstitutedSelectionTails> {
    let base_preparation = base.preparation_selection_tail();
    let preparation_selection_id =
        if matches!(substitution, IdentitySubstitution::PreparationOrigin) {
            base.activation_selection_tail().selection_id()
        } else {
            base_preparation.selection_id()
        };
    let preparation_claimed_at = if matches!(substitution, IdentitySubstitution::PreparationTail) {
        UnixMillis::new(base_preparation.claimed_at().get() + 1)
    } else {
        base_preparation.claimed_at()
    };
    let preparation = GithubRuntimeAuthorityPreparationSelectionTail::new(
        preparation_selection_id,
        base_preparation.owner(),
        base_preparation.generation(),
        base_preparation.descriptor_digest(),
        preparation_claimed_at,
        base_preparation.expires_at(),
    )?;

    let base_activation = base.activation_selection_tail();
    let activation_selection_id = if matches!(substitution, IdentitySubstitution::ActivationOrigin)
    {
        base.preparation_selection_tail().selection_id()
    } else {
        base_activation.selection_id()
    };
    let activation_claimed_at = if matches!(substitution, IdentitySubstitution::ActivationTail) {
        UnixMillis::new(base_activation.claimed_at().get() + 1)
    } else {
        base_activation.claimed_at()
    };
    let activation = GithubRuntimeAuthorityActivationSelectionTail::new(
        activation_selection_id,
        base_activation.owner(),
        base_activation.generation(),
        base_activation.activation_input_digest(),
        activation_claimed_at,
        base_activation.expires_at(),
    )?;

    let base_materialization = base.materialization_selection_tail();
    let materialization_selection_id =
        if matches!(substitution, IdentitySubstitution::MaterializationOrigin) {
            base.activation_selection_tail().selection_id()
        } else {
            base_materialization.selection_id()
        };
    let materialization_claimed_at =
        if matches!(substitution, IdentitySubstitution::MaterializationTail) {
            UnixMillis::new(base_materialization.claimed_at().get() + 1)
        } else {
            base_materialization.claimed_at()
        };
    let materialization = GithubRuntimeAuthorityMaterializationSelectionTail::new(
        materialization_selection_id,
        base_materialization.owner(),
        base_materialization.generation(),
        base_materialization.descriptor_digest(),
        materialization_claimed_at,
        base_materialization.expires_at(),
    )?;

    Ok(SubstitutedSelectionTails {
        preparation,
        activation,
        materialization,
    })
}

fn substituted_identity(
    base: &GithubRuntimeAuthorityIdentity,
    substitution: IdentitySubstitution,
) -> TestResult<GithubRuntimeAuthorityIdentity> {
    let provider = substituted_provider_identity(base, substitution)?;
    let tails = substituted_selection_tails(base, substitution)?;
    Ok(GithubRuntimeAuthorityIdentity::new(
        base.tenant().clone(),
        base.key().attempt_id(),
        base.key().fencing_token(),
        base.lease_id(),
        base.lease_issued_at(),
        base.lease_expires_at(),
        base.run_id(),
        base.job_id(),
        base.runner_id(),
        base.runner_session_id(),
        base.runner_session_epoch(),
        base.runner_generation(),
        base.runner_slot(),
        base.job_ir_version(),
        base.job_ir_size_bytes(),
        base.job_ir_digest(),
        base.repository_id(),
        provider.connection_id,
        provider.installation_id,
        provider.app_id,
        provider.app_client_id,
        provider.app_jwt_issuer_kind,
        provider.repository_id,
        base.github_repository_name().clone(),
        base.namespace().clone(),
        provider.policy_digest,
        provider.app_key_spki_sha256,
        provider.configuration_fingerprint,
        tails.preparation,
        tails.activation,
        tails.materialization,
        base.requested_at(),
        base.request_deadline(),
    )?)
}

const INSERT_EXACT_RUNTIME_AUTHORITY_CANDIDATE_SQL: &str = r"
        INSERT INTO github_runtime_authority_issuances (
            tenant_id, attempt_id, fencing_token, lease_id,
            lease_issued_at_ms, lease_expires_at_ms, run_id, job_id,
            runner_id, runner_session_id, runner_session_epoch,
            runner_generation, runner_slot, job_ir_schema,
            job_ir_size_bytes, job_ir_digest, repository_id,
            provider_connection_id, provider_installation_id,
            github_app_id, github_app_client_id,
            github_app_jwt_issuer_kind, github_app_jwt_issuer_value,
            github_repository_id, github_repository_name,
            authority_namespace, policy_digest, issuer_fingerprint,
            configuration_fingerprint,
            preparation_selection_id, preparation_selection_owner_id,
            preparation_selection_generation,
            preparation_selection_descriptor_digest,
            preparation_selection_claimed_at_ms,
            preparation_selection_expires_at_ms,
            activation_selection_id, activation_selection_owner_id,
            activation_selection_generation, activation_selection_input_digest,
            activation_selection_claimed_at_ms, activation_selection_expires_at_ms,
            materialization_selection_id, materialization_selection_owner_id,
            materialization_selection_generation,
            materialization_selection_descriptor_digest,
            materialization_selection_claimed_at_ms,
            materialization_selection_expires_at_ms,
            requested_at_ms,
            request_deadline_at_ms, conservative_expiry_at_ms,
            mint_claim_owner_id, mint_claimed_at_ms,
            mint_claim_expires_at_ms, state_updated_at_ms
        )
        SELECT repository.tenant_id, attempt.id, attempt.fencing_token,
               attempt.lease_id, attempt.lease_issued_at_ms,
               attempt.lease_expires_at_ms, run.id, job.id,
               attempt.runner_id, attempt.runner_session_id,
               attempt.runner_session_epoch, attempt.runner_generation,
               attempt.runner_slot, job.job_ir_schema, job.job_ir_size_bytes,
               job.job_ir_digest, repository.id,
               delivery.provider_connection_id,
               delivery.provider_installation_id,
               manifest.github_app_id, manifest.github_app_client_id,
               manifest.github_app_jwt_issuer_kind,
               CASE manifest.github_app_jwt_issuer_kind
                   WHEN 'app_client_id' THEN manifest.github_app_client_id
                   WHEN 'app_id' THEN manifest.github_app_id::TEXT
               END,
               delivery.github_repository_id, delivery.github_repository_name,
               'github.repository', job.job_ir_digest,
               manifest.app_key_spki_sha256,
               checks_authority.configuration_fingerprint,
               preparation.origin_selection_id, preparation.owner_id,
               preparation.generation, preparation.descriptor_digest,
               preparation.claimed_at_ms, preparation.expires_at_ms,
               logical_job.activation_origin_selection_id,
               publication.activation_owner_id, publication.activation_generation,
               publication.activation_input_digest,
               publication.activation_claimed_at_ms,
               publication.activation_expires_at_ms,
               materialization.origin_selection_id, materialization.owner_id,
               materialization.generation, materialization.descriptor_digest,
               materialization.claimed_at_ms, materialization.expires_at_ms,
               attempt.lease_issued_at_ms,
               LEAST(attempt.lease_expires_at_ms,
                     attempt.lease_issued_at_ms + 120000),
               LEAST(attempt.lease_expires_at_ms,
                     attempt.lease_issued_at_ms + 120000) + 3780000,
               'ffffffff-ffff-4fff-9fff-ffffffffffff'::UUID,
               database_time.now_ms,
               database_time.now_ms + 250,
               database_time.now_ms
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.job_id = job.id
         AND concrete.initial_attempt_id = attempt.id
        JOIN logical_workflow_activation_preparation_claims AS preparation
          ON preparation.run_id = concrete.run_id
         AND preparation.invocation_id = concrete.invocation_id
         AND preparation.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = concrete.run_id
         AND publication.invocation_id = concrete.invocation_id
         AND publication.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
        JOIN github_workflow_run_subject_evidence AS subject
          ON subject.tenant_id = repository.tenant_id
         AND subject.repository_id = repository.id
         AND subject.workflow_id = run.workflow_id
         AND subject.run_id = run.id
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        JOIN github_server_service_authorities AS checks_authority
          ON checks_authority.tenant_id = delivery.tenant_id
         AND checks_authority.id = delivery.checks_authority_id
        CROSS JOIN LATERAL (
            SELECT floor(
                extract(epoch FROM clock_timestamp()) * 1000
            )::BIGINT AS now_ms
        ) AS database_time
        WHERE attempt.id = $1
        ";

async fn insert_exact_runtime_authority_candidate(
    database: &TestDatabase,
    execution: &GithubJobRuntimeAuthorityExecution,
) -> Result<(), sqlx::Error> {
    sqlx::query(INSERT_EXACT_RUNTIME_AUTHORITY_CANDIDATE_SQL)
        .bind(execution.lease().attempt_id().as_uuid())
        .execute(database.pool())
        .await
        .map(|_| ())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn public_resolution_is_exact_and_rejects_every_execution_substitution() -> TestResult {
    run_with_database(|database| async move {
        let (execution, manifest) =
            seed_execution(&database, 100_000, ProviderRepositoryVisibility::Public).await?;
        let resolution = database
            .store()
            .resolve_github_job_runtime_authority(&execution)
            .await?;
        let identity = exact_standard_identity(resolution, &execution, &manifest)?;
        assert_eq!(
            database
                .store()
                .revalidate_github_job_runtime_authority(&identity)
                .await?
                .identity(),
            &identity
        );

        let wrong_owner = execution_variant(
            &execution,
            execution.workflow_id(),
            GithubRepositoryName::new("foreign/project")?,
            JobAuthorityProfile::Standard,
            execution.lease().clone(),
            execution.session(),
            execution.job_ir().clone(),
        )?;
        assert_unauthorized(
            database
                .store()
                .resolve_github_job_runtime_authority(&wrong_owner)
                .await,
            "repository owner",
        );

        let wrong_repository = execution_variant(
            &execution,
            execution.workflow_id(),
            GithubRepositoryName::new("example/foreign")?,
            JobAuthorityProfile::Standard,
            execution.lease().clone(),
            execution.session(),
            execution.job_ir().clone(),
        )?;
        assert_unauthorized(
            database
                .store()
                .resolve_github_job_runtime_authority(&wrong_repository)
                .await,
            "repository name",
        );

        let wrong_workflow = execution_variant(
            &execution,
            WorkflowId::new(),
            execution.github_repository_name().clone(),
            JobAuthorityProfile::Standard,
            execution.lease().clone(),
            execution.session(),
            execution.job_ir().clone(),
        )?;
        assert_unauthorized(
            database
                .store()
                .resolve_github_job_runtime_authority(&wrong_workflow)
                .await,
            "workflow",
        );

        let wrong_profile = execution_variant(
            &execution,
            execution.workflow_id(),
            execution.github_repository_name().clone(),
            JobAuthorityProfile::CredentialFree,
            execution.lease().clone(),
            execution.session(),
            execution.job_ir().clone(),
        )?;
        assert_unauthorized(
            database
                .store()
                .resolve_github_job_runtime_authority(&wrong_profile)
                .await,
            "authority profile",
        );

        let wrong_lease = execution_variant(
            &execution,
            execution.workflow_id(),
            execution.github_repository_name().clone(),
            JobAuthorityProfile::Standard,
            Lease::new(
                LeaseId::new(),
                execution.lease().attempt_id(),
                execution.lease().runner_id(),
                execution.lease().fencing_token(),
                execution.lease().issued_at(),
                execution.lease().expires_at(),
            )?,
            execution.session(),
            execution.job_ir().clone(),
        )?;
        assert_unauthorized(
            database
                .store()
                .resolve_github_job_runtime_authority(&wrong_lease)
                .await,
            "lease",
        );

        let wrong_fence = execution_variant(
            &execution,
            execution.workflow_id(),
            execution.github_repository_name().clone(),
            JobAuthorityProfile::Standard,
            Lease::new(
                execution.lease().lease_id(),
                execution.lease().attempt_id(),
                execution.lease().runner_id(),
                FencingToken::new(execution.lease().fencing_token().get() + 1)?,
                execution.lease().issued_at(),
                execution.lease().expires_at(),
            )?,
            execution.session(),
            execution.job_ir().clone(),
        )?;
        assert_unauthorized(
            database
                .store()
                .resolve_github_job_runtime_authority(&wrong_fence)
                .await,
            "lease fence",
        );

        let wrong_session = execution_variant(
            &execution,
            execution.workflow_id(),
            execution.github_repository_name().clone(),
            JobAuthorityProfile::Standard,
            execution.lease().clone(),
            RunnerSessionFence::new(
                RunnerSessionId::new(),
                execution.session().runner_id(),
                execution.session().runner_generation(),
                execution.session().session_epoch(),
            ),
            execution.job_ir().clone(),
        )?;
        assert_unauthorized(
            database
                .store()
                .resolve_github_job_runtime_authority(&wrong_session)
                .await,
            "runner session",
        );

        let wrong_job_ir = JobIrMetadata::new(
            execution.job_ir().job_id(),
            execution.job_ir().run_id(),
            execution.job_ir().version(),
            execution.job_ir().encoded_size(),
            digest(0xa1),
            execution.job_ir().object_key().clone(),
        )?;
        let wrong_job_ir = execution_variant(
            &execution,
            execution.workflow_id(),
            execution.github_repository_name().clone(),
            JobAuthorityProfile::Standard,
            execution.lease().clone(),
            execution.session(),
            wrong_job_ir,
        )?;
        assert_unauthorized(
            database
                .store()
                .resolve_github_job_runtime_authority(&wrong_job_ir)
                .await,
            "JobIR",
        );

        for (label, substitution) in [
            (
                "provider connection",
                IdentitySubstitution::ProviderConnection,
            ),
            (
                "provider installation",
                IdentitySubstitution::ProviderInstallation,
            ),
            ("GitHub App ID", IdentitySubstitution::GithubAppId),
            (
                "GitHub App client ID",
                IdentitySubstitution::GithubAppClientId,
            ),
            (
                "GitHub App JWT issuer kind",
                IdentitySubstitution::GithubAppJwtIssuerKind,
            ),
            (
                "GitHub repository ID",
                IdentitySubstitution::GithubRepository,
            ),
            ("App key SPKI", IdentitySubstitution::AppKeySpki),
            (
                "configuration fingerprint",
                IdentitySubstitution::ConfigurationFingerprint,
            ),
            (
                "preparation selection origin",
                IdentitySubstitution::PreparationOrigin,
            ),
            (
                "preparation renewal tail",
                IdentitySubstitution::PreparationTail,
            ),
            (
                "activation selection origin",
                IdentitySubstitution::ActivationOrigin,
            ),
            (
                "activation renewal tail",
                IdentitySubstitution::ActivationTail,
            ),
            (
                "materialization selection origin",
                IdentitySubstitution::MaterializationOrigin,
            ),
            (
                "materialization renewal tail",
                IdentitySubstitution::MaterializationTail,
            ),
        ] {
            let substituted = substituted_identity(&identity, substitution)?;
            assert_unauthorized(
                database
                    .store()
                    .revalidate_github_job_runtime_authority(&substituted)
                    .await,
                label,
            );
        }
        assert_phase_selection_origins_are_immutable(&database, execution.job_id()).await?;
        assert!(
            substituted_identity(&identity, IdentitySubstitution::PolicyDigest).is_err(),
            "policy and JobIR digest disagreement must fail in the domain"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn delayed_first_authority_issue_retains_completed_selection_lineage() -> TestResult {
    run_with_database(|database| async move {
        const FROZEN_NOW: i64 = 2_300_000_000_000;
        let clock = install_database_test_clock(&database, FROZEN_NOW).await?;
        let (execution, manifest) =
            seed_execution(&database, 150_000, ProviderRepositoryVisibility::Public).await?;

        set_database_test_clock(&clock, FROZEN_NOW + 240_000).await?;
        for _ in 0..2 {
            let observed_at = database_now(&database).await?;
            let activation = database
                .store()
                .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
                    LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
                    LogicalActivationWorkerId::from_uuid(Uuid::new_v4())?,
                    observed_at,
                    60_000,
                )?)
                .await?;
            assert!(matches!(
                activation,
                LogicalJobOrchestrationSelectionOutcome::Idle
            ));

            let materialization = database
                .store()
                .claim_next_logical_instance_materialization(
                    ClaimNextLogicalInstanceMaterialization::new(
                        LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
                        LogicalMaterializationWorkerId::from_uuid(Uuid::new_v4())?,
                        observed_at,
                        60_000,
                    )?,
                )
                .await?;
            assert!(matches!(
                materialization,
                LogicalInstanceMaterializationSelectionOutcome::Idle
            ));
        }

        let retained: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*)::BIGINT
                 FROM logical_workflow_activation_work_selections AS selection
                 JOIN logical_workflow_concrete_jobs AS concrete
                   ON concrete.run_id = selection.run_id
                  AND concrete.invocation_id = selection.invocation_id
                  AND concrete.logical_job_id = selection.logical_job_id
                 WHERE concrete.job_id = $1 AND selection.outcome = 'claimed'),
                (SELECT count(*)::BIGINT
                 FROM logical_workflow_materialization_work_selections AS selection
                 JOIN logical_workflow_materialization_claims AS materialization
                   ON materialization.origin_selection_id = selection.selection_id
                 WHERE materialization.expected_job_id = $1
                   AND selection.outcome = 'claimed')
            ",
        )
        .bind(execution.job_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(retained, (2, 1));

        let resolution = database
            .store()
            .resolve_github_job_runtime_authority(&execution)
            .await?;
        exact_standard_identity(resolution, &execution, &manifest)?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn private_resolution_requires_and_returns_the_exact_historical_installation() -> TestResult {
    run_with_database(|database| async move {
        let (execution, manifest) =
            seed_execution(&database, 200_000, ProviderRepositoryVisibility::Private).await?;
        let resolution = database
            .store()
            .resolve_github_job_runtime_authority(&execution)
            .await?;
        let identity = exact_standard_identity(resolution, &execution, &manifest)?;
        let revalidated = database
            .store()
            .revalidate_github_job_runtime_authority(&identity)
            .await?;
        assert_eq!(revalidated.identity(), &identity);
        assert_eq!(
            identity.provider_installation_id(),
            manifest.installation_id()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn current_manifest_rotation_cannot_reinterpret_historical_standard_authority() -> TestResult
{
    run_with_database(|database| async move {
        let (execution, manifest) =
            seed_execution(&database, 300_000, ProviderRepositoryVisibility::Public).await?;
        let rotated_at = database_now(&database).await?;
        database
            .store()
            .bootstrap_github_provider_repository(
                github_manifest_fixture::fixture_github_repository_bootstrap(
                    rotated_credential_free_manifest(&manifest),
                    rotated_at,
                ),
            )
            .await?;

        let resolution = database
            .store()
            .resolve_github_job_runtime_authority(&execution)
            .await?;
        let identity = exact_standard_identity(resolution, &execution, &manifest)?;
        assert_eq!(identity.provider_connection_id(), manifest.connection_id());
        assert_eq!(
            identity.app_key_spki_sha256(),
            manifest.app_key_spki_sha256()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One test keeps the lock-wait, expiry, and takeover proof adjacent.
async fn revocation_revalidation_samples_database_time_after_lock_and_rejects_stale_fence()
-> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let (execution, manifest) =
            seed_execution(&database, 350_000, ProviderRepositoryVisibility::Public).await?;
        let resolution = database
            .store()
            .resolve_github_job_runtime_authority(&execution)
            .await?;
        let identity = exact_standard_identity(resolution, &execution, &manifest)?;
        let preparation_and_materialization_are_distinct: bool = sqlx::query_scalar(
            r"
            SELECT preparation.descriptor_digest <> concrete.descriptor_digest
            FROM logical_workflow_concrete_jobs AS concrete
            JOIN logical_workflow_activation_preparation_claims AS preparation
              ON preparation.run_id = concrete.run_id
             AND preparation.invocation_id = concrete.invocation_id
             AND preparation.logical_job_id = concrete.logical_job_id
            WHERE concrete.job_id = $1
            ",
        )
        .bind(execution.job_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(
            preparation_and_materialization_are_distinct,
            "the fixture must prove independent preparation and materialization tails"
        );
        let mint_owner = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4())?;
        let mint_claim = database
            .store()
            .claim_github_runtime_authority_mint(ClaimGithubRuntimeAuthorityMint::new(
                identity.clone(),
                mint_owner,
                identity.requested_at(),
                UnixMillis::new(
                    identity
                        .requested_at()
                        .get()
                        .checked_add(60_000)
                        .ok_or("mint claim expiry")?,
                ),
            )?)
            .await?
            .ok_or("mint claim was not issued")?;
        assert!(matches!(
            database
                .store()
                .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                    mint_claim.clone(),
                    mint_claim.claimed_at(),
                    1_000,
                )?)
                .await?,
            BeginGithubRuntimeAuthorityMintOutcome::Started(_)
        ));
        let receipt = database
            .store()
            .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::revoke_only(
                &mint_claim,
                protected_runtime_authority(identity.clone())?,
                mint_claim.claimed_at(),
            )?)
            .await?;
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::RevokePending);
        let first_owner = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4())?;
        let first_claim = database
            .store()
            .claim_github_runtime_authority_revocation(ClaimGithubRuntimeAuthorityRevocation::new(
                first_owner,
                identity.requested_at(),
                UnixMillis::new(
                    identity
                        .requested_at()
                        .get()
                        .checked_add(700)
                        .ok_or("revocation claim expiry")?,
                ),
            )?)
            .await?
            .ok_or("revocation claim was not issued")?;
        let first_revalidation = RevalidateGithubRuntimeAuthorityRevocation::new(&first_claim, 50)?;
        let immediate = database
            .store()
            .revalidate_github_runtime_authority_revocation(first_revalidation)
            .await?
            .ok_or("live revocation claim did not revalidate")?;
        assert!(immediate.provider_call_authorized());

        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query(
            r"
            SELECT attempt_id
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = $2
            FOR UPDATE
            ",
        )
        .bind(identity.key().attempt_id().as_uuid())
        .bind(i64::try_from(identity.key().fencing_token().get())?)
        .fetch_one(&mut *blocker)
        .await?;
        let store = database.store().clone();
        let delayed = tokio::spawn(async move {
            store
                .revalidate_github_runtime_authority_revocation(first_revalidation)
                .await
        });
        wait_for_direct_database_blocker(database.pool(), blocker_pid).await?;
        assert!(!delayed.is_finished(), "revalidation must remain blocked");
        clock
            .set(
                first_claim
                    .expires_at()
                    .get()
                    .checked_add(1)
                    .ok_or("runtime-authority revocation expiry clock overflow")?,
            )
            .await?;
        blocker.commit().await?;
        assert!(
            delayed.await??.is_none(),
            "database time sampled after the lock wait must reject the expired claim"
        );

        let second_owner = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4())?;
        let second_claim = database
            .store()
            .claim_github_runtime_authority_revocation(ClaimGithubRuntimeAuthorityRevocation::new(
                second_owner,
                identity.requested_at(),
                UnixMillis::new(
                    identity
                        .requested_at()
                        .get()
                        .checked_add(1_000)
                        .ok_or("replacement claim expiry")?,
                ),
            )?)
            .await?
            .ok_or("replacement revocation claim was not issued")?;
        assert!(second_claim.fence() > first_claim.fence());
        assert!(
            database
                .store()
                .revalidate_github_runtime_authority_revocation(first_revalidation)
                .await?
                .is_none(),
            "a superseded revocation fence must stay stale"
        );
        let replacement = database
            .store()
            .revalidate_github_runtime_authority_revocation(
                RevalidateGithubRuntimeAuthorityRevocation::new(&second_claim, 50)?,
            )
            .await?
            .ok_or("replacement revocation claim did not revalidate")?;
        assert!(replacement.provider_call_authorized());
        Ok(())
    })
    .await
}

async fn wait_for_direct_database_blocker(pool: &sqlx::PgPool, blocker_pid: i32) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_stat_activity AS activity
                    WHERE activity.datname = current_database()
                      AND $1 = ANY(pg_catalog.pg_blocking_pids(activity.pid))
                )
                ",
            )
            .bind(blocker_pid)
            .fetch_one(pool)
            .await?;
            if blocked {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "runtime-authority operation did not reach its expected database lock")??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // Direct-SQL evidence guards form one fail-closed matrix.
async fn runtime_authority_direct_sql_guards_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        const FROZEN_NOW: i64 = 2_400_000_000_000;
        let clock = install_database_test_clock(&database, FROZEN_NOW).await?;
        let (execution, manifest) =
            seed_execution(&database, 400_000, ProviderRepositoryVisibility::Public).await?;
        let resolution = database
            .store()
            .resolve_github_job_runtime_authority(&execution)
            .await?;
        let identity = exact_standard_identity(resolution, &execution, &manifest)?;
        insert_exact_runtime_authority_candidate(&database, &execution).await?;

        let issuer_mutation = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances
            SET github_app_id = github_app_id + 1
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(execution.lease().attempt_id().as_uuid())
        .bind(i64::try_from(execution.lease().fencing_token().get())?)
        .execute(database.pool())
        .await
        .expect_err("direct issuer mutation must fail");
        assert_eq!(
            issuer_mutation
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_runtime_authority_historical_provenance")
        );

        let captured_claims: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM github_runtime_authority_mint_claims
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(execution.lease().attempt_id().as_uuid())
        .bind(i64::try_from(execution.lease().fencing_token().get())?)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(captured_claims, 1);
        let predecessor_mutation = sqlx::query(
            r"
            UPDATE github_runtime_authority_mint_claims
            SET expires_at_ms = expires_at_ms + 1
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(execution.lease().attempt_id().as_uuid())
        .bind(i64::try_from(execution.lease().fencing_token().get())?)
        .execute(database.pool())
        .await
        .expect_err("captured mint predecessor must be immutable");
        assert_eq!(
            predecessor_mutation
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_runtime_authority_mint_claim_immutable")
        );

        let forged_receipt = sqlx::query(
            r"
            INSERT INTO github_runtime_authority_operation_receipts (
                tenant_id, attempt_id, fencing_token, operation_kind,
                claim_fence, operation_digest, disposition,
                claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
                result_state, result_updated_at_ms, result_terminal_reason,
                applied_at_ms
            )
            SELECT tenant_id, attempt_id, fencing_token, 'mint_commit',
                   mint_claim_fence, $3, 'applied', mint_claim_owner_id,
                   mint_claimed_at_ms, mint_claim_expires_at_ms,
                   state, state_updated_at_ms, terminal_reason, 0
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(execution.lease().attempt_id().as_uuid())
        .bind(i64::try_from(execution.lease().fencing_token().get())?)
        .bind(digest(0xa4).as_bytes().as_slice())
        .execute(database.pool())
        .await
        .expect_err("a receipt before its lifecycle transition must fail");
        assert_eq!(
            forged_receipt
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_runtime_authority_operation_receipt_transition_exact")
        );

        let forged_quarantine_receipt = sqlx::query(
            r"
            INSERT INTO github_runtime_authority_operation_receipts (
                tenant_id, attempt_id, fencing_token, operation_kind,
                claim_fence, operation_digest, disposition,
                claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
                result_state, result_updated_at_ms, result_terminal_reason,
                applied_at_ms
            )
            SELECT tenant_id, attempt_id, fencing_token, 'quarantine',
                   0, $3, 'applied', NULL, NULL, NULL,
                   state, state_updated_at_ms, terminal_reason, 0
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(execution.lease().attempt_id().as_uuid())
        .bind(i64::try_from(execution.lease().fencing_token().get())?)
        .bind(digest(0xa5).as_bytes().as_slice())
        .execute(database.pool())
        .await
        .expect_err("a quarantine receipt before quarantine must fail");
        assert_eq!(
            forged_quarantine_receipt
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_runtime_authority_operation_receipt_transition_exact")
        );

        let truncate = sqlx::query("TRUNCATE github_runtime_authority_operation_receipts")
            .execute(database.pool())
            .await
            .expect_err("receipt truncation must fail even while empty");
        assert_eq!(
            truncate
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_runtime_authority_operation_receipt_truncate")
        );

        for (statement, constraint) in [
            (
                "TRUNCATE github_runtime_authority_mint_begins, \
                 github_runtime_authority_mint_claims",
                "github_runtime_authority_claim_evidence_truncate",
            ),
            (
                "TRUNCATE github_runtime_authority_revocation_claims",
                "github_runtime_authority_claim_evidence_truncate",
            ),
        ] {
            let truncate = sqlx::query(statement)
                .execute(database.pool())
                .await
                .expect_err("claim evidence truncation must fail even while empty");
            assert_eq!(
                truncate
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::constraint),
                Some(constraint)
            );
        }

        set_database_test_clock(&clock, FROZEN_NOW + 300).await?;
        let backdated_begin = sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances
            SET state = 'minting',
                mint_claim_expires_at_ms = NULL,
                mint_started_at_ms = mint_claimed_at_ms,
                state_updated_at_ms = mint_claimed_at_ms
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(execution.lease().attempt_id().as_uuid())
        .bind(i64::try_from(execution.lease().fencing_token().get())?)
        .execute(database.pool())
        .await
        .expect_err("a caller-backdated begin cannot resurrect an expired claim");
        assert_eq!(
            backdated_begin
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_runtime_authority_mint_begin_database_time")
        );

        let mint_owner = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4())?;
        let mint_claim = database
            .store()
            .claim_github_runtime_authority_mint(ClaimGithubRuntimeAuthorityMint::new(
                identity.clone(),
                mint_owner,
                identity.requested_at(),
                UnixMillis::new(
                    identity
                        .requested_at()
                        .get()
                        .checked_add(60_000)
                        .ok_or("replacement mint claim expiry")?,
                ),
            )?)
            .await?
            .ok_or("replacement mint claim was not issued")?;
        assert!(matches!(
            database
                .store()
                .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                    mint_claim.clone(),
                    mint_claim.claimed_at(),
                    1_000,
                )?)
                .await?,
            BeginGithubRuntimeAuthorityMintOutcome::Started(_)
        ));
        let forged_pre_commit_receipt = sqlx::query(
            r"
            INSERT INTO github_runtime_authority_operation_receipts (
                tenant_id, attempt_id, fencing_token, operation_kind,
                claim_fence, operation_digest, disposition,
                claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
                result_state, result_updated_at_ms, result_terminal_reason,
                applied_at_ms
            )
            SELECT authority.tenant_id, authority.attempt_id,
                   authority.fencing_token, 'mint_commit',
                   claim.claim_fence, $3, 'applied', claim.claim_owner_id,
                   claim.claimed_at_ms, claim.expires_at_ms,
                   authority.state, authority.state_updated_at_ms,
                   authority.terminal_reason, 0
            FROM github_runtime_authority_issuances AS authority
            JOIN github_runtime_authority_mint_claims AS claim
              ON claim.attempt_id = authority.attempt_id
             AND claim.fencing_token = authority.fencing_token
             AND claim.claim_fence = authority.mint_claim_fence
            WHERE authority.attempt_id = $1 AND authority.fencing_token = $2
            ",
        )
        .bind(execution.lease().attempt_id().as_uuid())
        .bind(i64::try_from(execution.lease().fencing_token().get())?)
        .bind(digest(0xa6).as_bytes().as_slice())
        .execute(database.pool())
        .await
        .expect_err("a mint receipt before commit must fail");
        assert_eq!(
            forged_pre_commit_receipt
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_runtime_authority_operation_receipt_transition_exact")
        );

        let receipt = database
            .store()
            .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::revoke_only(
                &mint_claim,
                protected_runtime_authority(identity.clone())?,
                mint_claim.claimed_at(),
            )?)
            .await?;
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::RevokePending);
        let revoke_owner = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4())?;
        let revoke_claim = database
            .store()
            .claim_github_runtime_authority_revocation(ClaimGithubRuntimeAuthorityRevocation::new(
                revoke_owner,
                identity.requested_at(),
                UnixMillis::new(
                    identity
                        .requested_at()
                        .get()
                        .checked_add(60_000)
                        .ok_or("revocation claim expiry")?,
                ),
            )?)
            .await?
            .ok_or("revocation claim was not issued")?;
        let forged_pre_outcome_receipt = sqlx::query(
            r"
            INSERT INTO github_runtime_authority_operation_receipts (
                tenant_id, attempt_id, fencing_token, operation_kind,
                claim_fence, operation_digest, disposition,
                claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
                result_state, result_updated_at_ms, result_terminal_reason,
                applied_at_ms
            )
            SELECT authority.tenant_id, authority.attempt_id,
                   authority.fencing_token, 'revocation_outcome',
                   claim.claim_fence, $3, 'applied', claim.claim_owner_id,
                   claim.claimed_at_ms, claim.expires_at_ms,
                   authority.state, authority.state_updated_at_ms,
                   authority.terminal_reason, 0
            FROM github_runtime_authority_issuances AS authority
            JOIN github_runtime_authority_revocation_claims AS claim
              ON claim.attempt_id = authority.attempt_id
             AND claim.fencing_token = authority.fencing_token
             AND claim.claim_fence = authority.revoke_claim_fence
            WHERE authority.attempt_id = $1 AND authority.fencing_token = $2
            ",
        )
        .bind(execution.lease().attempt_id().as_uuid())
        .bind(i64::try_from(execution.lease().fencing_token().get())?)
        .bind(digest(0xa7).as_bytes().as_slice())
        .execute(database.pool())
        .await
        .expect_err("a revocation receipt before its outcome must fail");
        assert_eq!(
            forged_pre_outcome_receipt
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_runtime_authority_operation_receipt_transition_exact")
        );
        assert_eq!(revoke_claim.key(), identity.key());
        Ok(())
    })
    .await
}

async fn assert_runtime_authority_inspection_waits_for_graph_lock(
    database: &TestDatabase,
    identity: &GithubRuntimeAuthorityIdentity,
    lock_sql: &'static str,
    locked_id: Uuid,
) -> TestResult {
    let mut blocker = database.pool().begin().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let locked = sqlx::query(lock_sql)
        .bind(locked_id)
        .fetch_all(&mut *blocker)
        .await?;
    if locked.is_empty() {
        return Err("runtime-authority graph lock fixture selected no row".into());
    }

    let store = database.store().clone();
    let request = InspectGithubRuntimeAuthority::new(
        identity.clone(),
        UnixMillis::new(identity.requested_at().get() + 1),
    )?;
    let inspection =
        tokio::spawn(async move { store.inspect_github_runtime_authority(request).await });
    wait_for_direct_database_blocker(database.pool(), blocker_pid).await?;
    blocker.rollback().await?;
    assert!(inspection.await??.is_some());
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn runtime_authority_locks_attempt_runner_session_and_historical_manifest() -> TestResult {
    run_with_database(|database| async move {
        let _clock = install_database_test_clock(&database, 2_500_000_000_000).await?;
        let (execution, manifest) =
            seed_execution(&database, 500_000, ProviderRepositoryVisibility::Public).await?;
        let resolution = database
            .store()
            .resolve_github_job_runtime_authority(&execution)
            .await?;
        let identity = exact_standard_identity(resolution, &execution, &manifest)?;
        insert_exact_runtime_authority_candidate(&database, &execution).await?;

        for (lock_sql, locked_id) in [
            (
                "SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE",
                identity.key().attempt_id().as_uuid(),
            ),
            (
                "SELECT id FROM runners WHERE id = $1 FOR UPDATE",
                identity.runner_id().as_uuid(),
            ),
            (
                "SELECT id FROM runner_sessions WHERE id = $1 FOR UPDATE",
                identity.runner_session_id().as_uuid(),
            ),
            (
                "SELECT workflow.id FROM workflow_definitions AS workflow \
                 JOIN workflow_runs AS run ON run.workflow_id = workflow.id \
                 WHERE run.id = $1 FOR UPDATE OF workflow",
                identity.run_id().as_uuid(),
            ),
            (
                "SELECT snapshot.id FROM workflow_snapshots AS snapshot \
                 JOIN workflow_runs AS run ON run.snapshot_id = snapshot.id \
                 WHERE run.id = $1 FOR UPDATE OF snapshot",
                identity.run_id().as_uuid(),
            ),
            (
                "SELECT repository_id FROM github_provider_manifest_revisions \
                 WHERE repository_id = $1 FOR UPDATE",
                identity.repository_id().as_uuid(),
            ),
            (
                "SELECT selection_id FROM logical_workflow_activation_work_selections \
                 WHERE selection_id = $1 FOR UPDATE",
                identity
                    .preparation_selection_tail()
                    .selection_id()
                    .as_uuid(),
            ),
            (
                "SELECT selection_id FROM logical_workflow_activation_work_selections \
                 WHERE selection_id = $1 FOR UPDATE",
                identity
                    .activation_selection_tail()
                    .selection_id()
                    .as_uuid(),
            ),
            (
                "SELECT selection_id FROM logical_workflow_materialization_work_selections \
                 WHERE selection_id = $1 FOR UPDATE",
                identity
                    .materialization_selection_tail()
                    .selection_id()
                    .as_uuid(),
            ),
            (
                "SELECT selection_id FROM logical_workflow_activation_renewal_receipts \
                 WHERE selection_id = $1 FOR UPDATE",
                identity
                    .preparation_selection_tail()
                    .selection_id()
                    .as_uuid(),
            ),
            (
                "SELECT selection_id FROM logical_workflow_activation_renewal_receipts \
                 WHERE selection_id = $1 FOR UPDATE",
                identity
                    .activation_selection_tail()
                    .selection_id()
                    .as_uuid(),
            ),
            (
                "SELECT selection_id FROM logical_workflow_materialization_renewal_receipts \
                 WHERE selection_id = $1 FOR UPDATE",
                identity
                    .materialization_selection_tail()
                    .selection_id()
                    .as_uuid(),
            ),
        ] {
            assert_runtime_authority_inspection_waits_for_graph_lock(
                &database, &identity, lock_sql, locked_id,
            )
            .await?;
        }
        Ok(())
    })
    .await
}
