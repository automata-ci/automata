mod common;
mod github_manifest_fixture;

use std::{collections::BTreeMap, time::Duration};

use automata_ci_core::{
    Architecture, AttemptId, ContextValue, FencingToken, JobAuthorityProfile, JobContentReference,
    JobExecutionContext, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobIrVersion,
    JobLifecycle, JobRuntimeContext, JobSource, Lease, LeaseId, OperatingSystem, OperationId,
    RunId, RunValueTemplates, RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    StrategyContext, UnixMillis, ValueTemplate, WorkflowJobKey,
};
use automata_ci_key_management::{ENVELOPE_SCHEMA_V1, EncryptedEnvelope, KeyId, WrappedDataKey};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AttemptStoreError, AuthenticateGithubRuntimeAuthorityUnprotectedErasure,
    AuthenticatedGithubDeliveryClaim, BeginGithubRuntimeAuthorityMint,
    BeginGithubRuntimeAuthorityMintOutcome, BindLogicalActivationPreparation,
    ClaimGithubRuntimeAuthorityMint, ClaimGithubRuntimeAuthorityRevocation,
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ClaimProviderDelivery, ClaimedGithubRuntimeAuthorityMint,
    ClaimedGithubRuntimeAuthorityRevocation, ClaimedLogicalInstanceMaterialization,
    ClaimedLogicalJobActivation, CommandCursor, CommitGithubRuntimeAuthority, CommitLeaseHeartbeat,
    CommitLogicalInstanceMaterialization, ConfirmGithubRuntimeAuthorityRevocation,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, DeferGithubRuntimeAuthorityRevocation,
    DocumentSchema, EnsureGithubServerServiceAuthority, GithubCheckHeadSha, GithubCheckName,
    GithubJobRuntimeAuthorityExecution, GithubJobRuntimeAuthorityRepository as _,
    GithubJobRuntimeAuthorityResolution, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName,
    GithubRuntimeAuthorityCommitDisposition, GithubRuntimeAuthorityCorruptionKind,
    GithubRuntimeAuthorityEnvelopeMetadata, GithubRuntimeAuthorityIdentity,
    GithubRuntimeAuthorityMintFailure, GithubRuntimeAuthorityRepository as _,
    GithubRuntimeAuthorityRevocationFailure, GithubRuntimeAuthorityState,
    GithubRuntimeAuthorityStoreError, GithubRuntimeAuthorityTerminalReason,
    GithubRuntimeAuthorityValueError, GithubRuntimeAuthorityWorkerId,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository as _,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubServerServiceScope,
    GithubSubjectEvidenceRepository as _, InspectGithubRuntimeAuthority,
    InternalAttemptRepository as _, JobEnvironmentActivationEvidence, JobEventTrust, JobSourceKind,
    LoadGithubRuntimeAuthority, LogicalActivationObject, LogicalActivationPreparationStore as _,
    LogicalActivationPreparationTarget, LogicalActivationRepository as _,
    LogicalActivationWorkerId, LogicalInstanceMaterializationSelectionOutcome,
    LogicalInstanceMaterializationTarget, LogicalJobOrchestrationSelectionOutcome,
    LogicalMaterializationRepository as _, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    LogicalWorkSelectionRepository as _, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind,
    MarkGithubRuntimeAuthorityIndeterminate, ObjectKey, OpenRunnerSession,
    ProtectedGithubRuntimeAuthority, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, PublishLogicalJobActivation, QuarantineGithubRuntimeAuthority,
    ReconcileGithubRuntimeAuthorities, RejectGithubRuntimeAuthorityMint, RenewLease,
    RetryGithubRuntimeAuthorityMint, RetryGithubRuntimeAuthorityRevocation,
    ReusableSecretPermission, RoutingDocument, RunnerControlTransactionRepository as _,
    RunnerGeneration, RunnerOperationKind, RunnerOperationRequest, RunnerOperationResponse,
    RunnerProtocolVersion, RunnerSessionRepository as _, StableRunnerSlot, StoreError, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowPlanRepository as _, WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

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

fn logical_fixture(namespace: u128, database_epoch: UnixMillis) -> LogicalFixture {
    let tenant = format!("runtime-authority-{}", Uuid::new_v4().simple());
    let tenant_scope = TenantScope::from_authenticated_tenant_id(&tenant).expect("tenant scope");
    let manifest = github_manifest(tenant_scope.clone(), namespace);
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
        WorkflowAdmissionIdempotency::provider_delivery(format!("runtime-authority-{namespace}"))
            .expect("idempotency"),
        digest(0x40),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            manifest.github_repository_id().get().to_string(),
            "automata-ci",
            "automata",
        )
        .expect("repository"),
        workflow_id,
        manifest.workflow_path(),
        "CI",
        "refs/heads/main",
        snapshot_id,
        admission_object(
            format!("runtime-authority/{namespace}/source"),
            0x11,
            "application/yaml",
        ),
        admission_object(
            format!("runtime-authority/{namespace}/plan"),
            0x12,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(
            format!("runtime-authority/{namespace}/event"),
            0x13,
            "application/json",
        ),
        vec![0x14; 20],
        vec![logical_job],
        database_epoch,
    )
    .base_context(admission_object(
        format!("runtime-authority/{namespace}/base-context"),
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

fn github_manifest(tenant: TenantScope, namespace: u128) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    GithubProviderManifest::new(
        tenant,
        ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 10)).expect("connection"),
        ProviderInstallationId::new(u64::try_from(namespace + 11).expect("installation"))
            .expect("installation"),
        ProviderRepositoryId::new(u64::try_from(namespace + 12).expect("repository ID"))
            .expect("repository ID"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(u64::try_from(namespace + 13).expect("App ID"))
            .expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.runtime-authority-test").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        digest(0x52),
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

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    Ok(UnixMillis::new(now))
}

async fn install_database_test_clock(database: &TestDatabase, now_ms: i64) -> TestResult {
    sqlx::query(
        r"
        CREATE TABLE github_runtime_authority_test_clock (
            singleton BOOLEAN PRIMARY KEY CHECK (singleton),
            now_ms BIGINT NOT NULL CHECK (now_ms >= 0)
        )
        ",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        "INSERT INTO github_runtime_authority_test_clock (singleton, now_ms) VALUES (TRUE, $1)",
    )
    .bind(now_ms)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        CREATE FUNCTION clock_timestamp()
        RETURNS TIMESTAMPTZ
        LANGUAGE SQL
        VOLATILE
        AS $automata_test$
            SELECT TIMESTAMPTZ 'epoch' + now_ms * INTERVAL '1 millisecond'
            FROM github_runtime_authority_test_clock
            WHERE singleton
        $automata_test$
        ",
    )
    .execute(database.pool())
    .await?;
    set_database_test_clock(database, now_ms).await
}

async fn set_database_test_clock(database: &TestDatabase, now_ms: i64) -> TestResult {
    let updated =
        sqlx::query("UPDATE github_runtime_authority_test_clock SET now_ms = $1 WHERE singleton")
            .bind(now_ms)
            .execute(database.pool())
            .await?;
    if updated.rows_affected() != 1 {
        return Err("runtime-authority test database clock is not installed".into());
    }
    let observed = database_now(database).await?;
    if observed.get() != now_ms {
        return Err("Store connection did not resolve the schema-local test clock".into());
    }
    Ok(())
}

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    let now = database_now(database).await?;
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) \
         VALUES ($1, 'Runtime authority test', $2, $2)",
    )
    .bind(tenant)
    .bind(now.get())
    .execute(database.pool())
    .await?;
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

fn namespace_id(manifest: &GithubProviderManifest, suffix: u128) -> u128 {
    manifest.connection_id().as_uuid().as_u128() + 100 + suffix
}

fn service_authority(
    manifest: &GithubProviderManifest,
    id: u128,
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
        GithubServerServiceScope::ChecksWrite,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
        digest(0x53),
    )?)
}

async fn admit_signed_workflow(
    database: &TestDatabase,
    fixture: &mut LogicalFixture,
    database_epoch: UnixMillis,
) -> TestResult {
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
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            service_authority(manifest, namespace_id(manifest, 1))?,
            database_epoch,
        )?)
        .await
        .map_err(|error| format!("checks authority bootstrap failed: {error:?}"))?;
    let identity = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
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
                fixture.command.event().clone(),
                delivery_observed_at,
            )?,
            ProviderRepositoryOwnerId::new(404)?,
            ProviderRepositoryOwnerId::new(404)?,
            GithubCheckHeadSha::new(head_sha)?,
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
        )?)
        .await
        .map_err(|error| format!("delivery acceptance failed: {error:?}"))?;
    let claim_observed_at = database_now(database).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4())?,
            claim_observed_at,
            UnixMillis::new(
                claim_observed_at
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
    Ok(database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?
        .authority()
        .clone())
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
    let workspace = "/srv/work/automata";
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
            "automata-ci/automata",
            "0123456789abcdef",
            fixture.manifest.workflow_path(),
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

#[allow(clippy::too_many_lines)]
async fn seed_execution(database: &TestDatabase) -> TestResult<GithubJobRuntimeAuthorityExecution> {
    let database_epoch = database_now(database).await?;
    let namespace = Uuid::new_v4().as_u128() & 0x0000_ffff_ffff_ffff;
    let mut fixture = logical_fixture(namespace, database_epoch);
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
    let materialized = database
        .store()
        .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
            &materialization,
            &prepared.encoded,
            &prepared.envelope,
            &prepared.runtime_encoded,
            &prepared.runtime_context,
            database_now(database).await?,
        )?)
        .await?;
    let runner_epoch = database_now(database).await?;
    let runner_id = RunnerId::new();
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
            RunnerProtocolVersion::new(4)?,
            JobIrVersion::current(),
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
    Ok(GithubJobRuntimeAuthorityExecution::new(
        fixture.command.workflow_id(),
        fixture.manifest.github_repository_name().clone(),
        JobAuthorityProfile::Standard,
        metadata.digest(),
        Lease::new(
            lease_id,
            materialized.attempt_id(),
            runner_id,
            fence,
            lease_epoch,
            UnixMillis::new(lease_expires_at),
        )?,
        session.fence(),
        StableRunnerSlot::new(1)?,
        metadata,
    )?)
}

#[derive(Clone)]
struct AuthorityFixture {
    identity: GithubRuntimeAuthorityIdentity,
}

impl AuthorityFixture {
    fn owner(value: u128) -> GithubRuntimeAuthorityWorkerId {
        GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::from_u128(value)).expect("worker")
    }

    fn claim(
        &self,
        owner: GithubRuntimeAuthorityWorkerId,
        observed_at: i64,
        expires_at: i64,
    ) -> ClaimGithubRuntimeAuthorityMint {
        self.claim_for(owner, (expires_at - observed_at).max(5_000))
    }

    fn claim_for(
        &self,
        owner: GithubRuntimeAuthorityWorkerId,
        duration_millis: i64,
    ) -> ClaimGithubRuntimeAuthorityMint {
        self.claim_for_at(owner, self.identity.requested_at(), duration_millis)
    }

    fn claim_for_at(
        &self,
        owner: GithubRuntimeAuthorityWorkerId,
        observed_at: UnixMillis,
        duration_millis: i64,
    ) -> ClaimGithubRuntimeAuthorityMint {
        ClaimGithubRuntimeAuthorityMint::new(
            self.identity.clone(),
            owner,
            observed_at,
            UnixMillis::new(observed_at.get() + duration_millis),
        )
        .expect("mint claim")
    }

    fn at(&self, offset: i64) -> UnixMillis {
        UnixMillis::new(self.identity.requested_at().get() + offset)
    }

    fn protected(&self) -> ProtectedGithubRuntimeAuthority {
        self.protected_with_expiry(Some(self.at(3_500_000)), 0x61, 0x62, 0x63, 0x64)
    }

    fn protected_without_provider_expiry(&self) -> ProtectedGithubRuntimeAuthority {
        self.protected_with_expiry(None, 0x71, 0x72, 0x73, 0x74)
    }

    fn protected_with_expiry(
        &self,
        provider_expires_at: Option<UnixMillis>,
        plaintext_digest: u8,
        wrapped_key: u8,
        nonce: u8,
        ciphertext: u8,
    ) -> ProtectedGithubRuntimeAuthority {
        let metadata = GithubRuntimeAuthorityEnvelopeMetadata::new(
            self.identity.clone(),
            provider_expires_at,
            32,
            Sha256Digest::from_bytes([plaintext_digest; 32]),
        )
        .expect("metadata");
        let wrapped = WrappedDataKey::new(
            KeyId::new("github-runtime-test-v1").expect("key ID"),
            vec![wrapped_key; 48],
        )
        .expect("wrapped key");
        let envelope = EncryptedEnvelope::from_parts(
            ENVELOPE_SCHEMA_V1,
            wrapped,
            [nonce; 12],
            vec![ciphertext; 48],
        )
        .expect("envelope");
        ProtectedGithubRuntimeAuthority::new(metadata, envelope).expect("protected authority")
    }
}

fn revocation_claim(
    owner: GithubRuntimeAuthorityWorkerId,
    duration_millis: i64,
) -> TestResult<ClaimGithubRuntimeAuthorityRevocation> {
    Ok(ClaimGithubRuntimeAuthorityRevocation::new(
        owner,
        UnixMillis::new(0),
        UnixMillis::new(duration_millis),
    )?)
}

async fn require_postgres_18(database: &TestDatabase) -> TestResult {
    let version: i32 =
        sqlx::query_scalar("SELECT pg_catalog.current_setting('server_version_num')::INTEGER")
            .fetch_one(database.pool())
            .await?;
    if version < 180_000 {
        return Err("runtime-authority concurrency tests require PostgreSQL 18".into());
    }
    Ok(())
}

async fn operation_receipt_snapshot(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
    operation_kind: &str,
    claim_fence: i64,
) -> TestResult<(String, Vec<u8>, String, i64)> {
    Ok(sqlx::query_as(
        r"
        SELECT disposition, operation_digest,
               result_state, result_updated_at_ms
        FROM github_runtime_authority_operation_receipts
        WHERE attempt_id = $1 AND fencing_token = 7
          AND operation_kind = $2 AND claim_fence = $3
        ",
    )
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .bind(operation_kind)
    .bind(claim_fence)
    .fetch_one(database.pool())
    .await?)
}

async fn assert_forged_mint_receipt_rejected(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
    mint: &ClaimedGithubRuntimeAuthorityMint,
) -> TestResult {
    let forged = sqlx::query(
        r"
        INSERT INTO github_runtime_authority_operation_receipts (
            tenant_id, attempt_id, fencing_token, operation_kind,
            claim_fence, operation_digest, disposition,
            claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
            result_state, result_updated_at_ms, result_terminal_reason,
            applied_at_ms
        ) VALUES (
            $1, $2, 7, 'mint_commit', $3, $4, 'applied',
            $5, $6, $7, 'ready', $6, NULL, 0
        )
        ",
    )
    .bind(fixture.identity.tenant().as_str())
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .bind(i64::try_from(mint.fence().get())?)
    .bind([0x90_u8; 32].as_slice())
    .bind(mint.owner().as_uuid())
    .bind(mint.claimed_at().get())
    .bind(mint.expires_at().get())
    .execute(database.pool())
    .await;
    assert!(
        forged.is_err(),
        "a mint receipt cannot forge its exact lifecycle transition"
    );
    Ok(())
}

async fn assert_forged_quarantine_receipt_rejected(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
) -> TestResult {
    let forged_result_at = database_now(database).await?;
    let forged = sqlx::query(
        r"
        INSERT INTO github_runtime_authority_operation_receipts (
            tenant_id, attempt_id, fencing_token, operation_kind,
            claim_fence, operation_digest, disposition,
            result_state, result_updated_at_ms, result_terminal_reason,
            applied_at_ms
        ) VALUES (
            $1, $2, 7, 'quarantine', 0, $3, 'applied',
            'quarantined', $4, NULL, 0
        )
        ",
    )
    .bind(fixture.identity.tenant().as_str())
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .bind([0x91_u8; 32].as_slice())
    .bind(forged_result_at.get())
    .execute(database.pool())
    .await;
    assert!(
        forged.is_err(),
        "a receipt cannot forge an operation transition"
    );
    Ok(())
}

async fn assert_forged_revocation_receipt_rejected(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
    claim: &ClaimedGithubRuntimeAuthorityRevocation,
) -> TestResult {
    let forged = sqlx::query(
        r"
        INSERT INTO github_runtime_authority_operation_receipts (
            tenant_id, attempt_id, fencing_token, operation_kind,
            claim_fence, operation_digest, disposition,
            claim_owner_id, claim_claimed_at_ms, claim_expires_at_ms,
            result_state, result_updated_at_ms, result_terminal_reason,
            applied_at_ms
        ) VALUES (
            $1, $2, 7, 'revocation_outcome', $3, $4, 'applied',
            $5, $6, $7, 'revoke_pending', $6, NULL, 0
        )
        ",
    )
    .bind(fixture.identity.tenant().as_str())
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .bind(i64::try_from(claim.fence().get())?)
    .bind([0x92_u8; 32].as_slice())
    .bind(claim.owner().as_uuid())
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .execute(database.pool())
    .await;
    assert!(
        forged.is_err(),
        "a revocation receipt cannot forge its exact lifecycle transition"
    );
    Ok(())
}

async fn assert_quarantine_transition_requires_receipt(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
) -> TestResult {
    let mut transaction = database.pool().begin().await?;
    let transition_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut *transaction)
            .await?;
    let changed = sqlx::query(
        r"
        UPDATE github_runtime_authority_issuances
        SET state = 'quarantined',
            revoke_claim_owner_id = NULL,
            revoke_claimed_at_ms = NULL,
            revoke_claim_expires_at_ms = NULL,
            next_revoke_at_ms = NULL,
            quarantine_at_ms = $2,
            quarantine_kind = 'invalid_envelope',
            state_updated_at_ms = $2,
            operation_request_kind = 'quarantine',
            operation_request_claim_fence = 0,
            operation_request_claim_owner_id = NULL,
            operation_request_observed_at_ms = $2,
            operation_request_retry_at_ms = NULL,
            operation_request_failure_kind = 'invalid_envelope',
            operation_request_commit_disposition = NULL,
            operation_request_provider_expires_at_ms = NULL,
            operation_request_safe_erase_after_ms = NULL,
            operation_request_plaintext_schema = NULL,
            operation_request_plaintext_size_bytes = NULL,
            operation_request_plaintext_digest = NULL,
            operation_request_aad_digest = aad_digest,
            operation_request_envelope_digest = NULL
        WHERE attempt_id = $1 AND fencing_token = 7
          AND state IN ('ready', 'revoke_pending')
        ",
    )
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .bind(transition_at)
    .execute(&mut *transaction)
    .await?;
    assert_eq!(changed.rows_affected(), 1);
    assert!(
        transaction.commit().await.is_err(),
        "the exact lifecycle transition cannot commit without its reciprocal receipt"
    );
    let retained: i64 = sqlx::query_scalar(
        r"
        SELECT count(*)
        FROM github_runtime_authority_operation_transitions
        WHERE attempt_id = $1 AND fencing_token = 7
          AND operation_kind = 'quarantine'
        ",
    )
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(retained, 0, "failed commit must roll back both halves");
    Ok(())
}

async fn assert_operation_evidence_is_immutable(database: &TestDatabase) -> TestResult {
    for statement in [
        "UPDATE github_runtime_authority_operation_receipts SET operation_digest = operation_digest",
        "DELETE FROM github_runtime_authority_operation_receipts",
        "TRUNCATE github_runtime_authority_operation_receipts",
        "UPDATE github_runtime_authority_operation_transitions SET result_state = result_state",
        "DELETE FROM github_runtime_authority_operation_transitions",
        "TRUNCATE github_runtime_authority_operation_transitions",
    ] {
        assert!(
            sqlx::query(statement)
                .execute(database.pool())
                .await
                .is_err(),
            "operation evidence mutation unexpectedly succeeded: {statement}"
        );
    }
    Ok(())
}

async fn assert_foreign_unprotected_claim_is_rejected(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
    mint: &ClaimedGithubRuntimeAuthorityMint,
) -> TestResult {
    let foreign_claim = ClaimedGithubRuntimeAuthorityMint::from_repository_parts(
        fixture.identity.clone(),
        AuthorityFixture::owner(411),
        mint.fence(),
        mint.attempt(),
        mint.claimed_at(),
        mint.expires_at(),
    )?;
    assert!(matches!(
        database
            .store()
            .authenticate_github_runtime_authority_unprotected_erasure(
                AuthenticateGithubRuntimeAuthorityUnprotectedErasure::new(&foreign_claim),
            )
            .await,
        Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
    ));
    Ok(())
}

async fn seed_authority(database: &TestDatabase) -> TestResult<AuthorityFixture> {
    require_postgres_18(database).await?;
    let execution = seed_execution(database).await?;
    let resolution = database
        .store()
        .resolve_github_job_runtime_authority(&execution)
        .await?;
    let GithubJobRuntimeAuthorityResolution::Standard(evidence) = resolution else {
        return Err("standard execution resolved without runtime authority".into());
    };
    let identity = evidence.identity().clone();
    Ok(AuthorityFixture { identity })
}

fn identity_with_provider(
    identity: &GithubRuntimeAuthorityIdentity,
    connection: u128,
    installation: u64,
) -> TestResult<GithubRuntimeAuthorityIdentity> {
    Ok(GithubRuntimeAuthorityIdentity::new(
        identity.tenant().clone(),
        identity.key().attempt_id(),
        identity.key().fencing_token(),
        identity.lease_id(),
        identity.lease_issued_at(),
        identity.lease_expires_at(),
        identity.run_id(),
        identity.job_id(),
        identity.runner_id(),
        identity.runner_session_id(),
        identity.runner_session_epoch(),
        identity.runner_generation(),
        identity.runner_slot(),
        identity.job_ir_version(),
        identity.job_ir_size_bytes(),
        identity.job_ir_digest(),
        identity.repository_id(),
        ProviderConnectionId::from_uuid(Uuid::from_u128(connection))?,
        ProviderInstallationId::new(installation)?,
        identity.github_app_id(),
        identity.github_app_client_id().clone(),
        identity.github_app_jwt_issuer_kind(),
        identity.github_repository_id(),
        identity.github_repository_name().clone(),
        identity.namespace().clone(),
        identity.policy_digest(),
        identity.app_key_spki_sha256(),
        identity.configuration_fingerprint(),
        identity.preparation_selection_tail(),
        identity.activation_selection_tail(),
        identity.materialization_selection_tail(),
        identity.requested_at(),
        identity.request_deadline(),
    )?)
}

async fn claim_single_mint_winner(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
) -> TestResult<ClaimedGithubRuntimeAuthorityMint> {
    let observed_at = database_now(database).await?;
    let mut tasks = Vec::new();
    for ordinal in 0..32_u128 {
        let store = database.store().clone();
        let request =
            fixture.claim_for_at(AuthorityFixture::owner(100 + ordinal), observed_at, 60_000);
        tasks.push(tokio::spawn(async move {
            store.claim_github_runtime_authority_mint(request).await
        }));
    }
    let mut claims = Vec::new();
    for task in tasks {
        if let Some(claim) = task.await?? {
            claims.push(claim);
        }
    }
    assert_eq!(claims.len(), 1);
    let winner = claims.pop().expect("one winner");
    assert_eq!(winner.attempt(), 1);
    Ok(winner)
}

async fn assert_pre_mint_terminal_transitions_rejected(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
) -> TestResult {
    let attempt_id = fixture.identity.key().attempt_id().as_uuid();
    assert!(
        sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances
            SET state = 'revoked',
                mint_claim_expires_at_ms = NULL,
                provider_expires_at_ms = 3500000,
                safe_erase_after_ms = 3620000,
                plaintext_schema = 1,
                plaintext_size_bytes = 32,
                plaintext_digest = $3,
                aad_digest = $4,
                revoked_at_ms = 50,
                terminal_reason = 'provider_authority_expired',
                state_updated_at_ms = 50
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(attempt_id)
        .bind(7_i64)
        .bind(vec![0x71_u8; 32])
        .bind(vec![0x72_u8; 32])
        .execute(database.pool())
        .await
        .is_err()
    );
    assert!(
        sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances
            SET state = 'revoked',
                mint_claim_expires_at_ms = NULL,
                revoked_at_ms = 50,
                terminal_reason = 'superseded_before_mint',
                state_updated_at_ms = 50
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(attempt_id)
        .bind(7_i64)
        .execute(database.pool())
        .await
        .is_err()
    );
    Ok(())
}

async fn reclaim_and_begin_mint(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
    stale_claim: ClaimedGithubRuntimeAuthorityMint,
) -> TestResult<ClaimedGithubRuntimeAuthorityMint> {
    tokio::time::sleep(Duration::from_millis(3_100)).await;
    let observed_at = database_now(database).await?;
    // This second claim proves takeover and mint-start fencing, not a short
    // expiry boundary. Leave enough live time for a hosted PostgreSQL WAL
    // checkpoint between the post-lock clock sample and the guarded update.
    let reclaimed = database
        .store()
        .claim_github_runtime_authority_mint(fixture.claim_for_at(
            AuthorityFixture::owner(200),
            observed_at,
            60_000,
        ))
        .await?
        .expect("expired pre-mint claim is reclaimable");
    assert_eq!(reclaimed.attempt(), 2);
    assert!(reclaimed.fence() > stale_claim.fence());
    let stale_observed_at = stale_claim.claimed_at();
    let stale_begin = BeginGithubRuntimeAuthorityMint::new(stale_claim, stale_observed_at, 1)?;
    assert!(matches!(
        database
            .store()
            .begin_github_runtime_authority_mint(stale_begin)
            .await,
        Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
    ));
    let begun = database
        .store()
        .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
            reclaimed.clone(),
            reclaimed.claimed_at(),
            1,
        )?)
        .await?;
    assert!(matches!(
        begun,
        BeginGithubRuntimeAuthorityMintOutcome::Started(receipt)
            if receipt.state() == GithubRuntimeAuthorityState::Minting
    ));
    Ok(reclaimed)
}

async fn assert_indeterminate_expiry(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
    reclaimed: &ClaimedGithubRuntimeAuthorityMint,
) -> TestResult {
    assert!(
        sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances
            SET state = 'indeterminate',
                indeterminate_at_ms = conservative_expiry_at_ms,
                state_updated_at_ms = conservative_expiry_at_ms
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .bind(7_i64)
        .execute(database.pool())
        .await
        .is_err()
    );
    assert!(
        database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim_for_at(
                AuthorityFixture::owner(201),
                database_now(database).await?,
                5_000,
            ))
            .await?
            .is_none()
    );
    let indeterminate = database
        .store()
        .mark_github_runtime_authority_indeterminate(MarkGithubRuntimeAuthorityIndeterminate::new(
            reclaimed,
            reclaimed.claimed_at(),
        )?)
        .await?;
    assert_eq!(
        indeterminate.state(),
        GithubRuntimeAuthorityState::Indeterminate
    );

    let report = database
        .store()
        .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
            fixture.identity.conservative_expiry(),
            16,
        )?)
        .await?;
    assert_eq!(report.indeterminate_authorities_expired(), 0);
    assert_eq!(report.expired_envelopes_erased(), 0);
    let durable: (String, Option<String>, Option<Vec<u8>>) = sqlx::query_as(
        r"
        SELECT state, terminal_reason, ciphertext
        FROM github_runtime_authority_issuances
        WHERE attempt_id = $1 AND fencing_token = 7
        ",
    )
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(durable, ("indeterminate".into(), None, None));
    Ok(())
}

async fn mint_ready_authority(database: &TestDatabase, fixture: &AuthorityFixture) -> TestResult {
    let mint = database
        .store()
        .claim_github_runtime_authority_mint(fixture.claim(AuthorityFixture::owner(300), 20, 100))
        .await?
        .expect("claim");
    database
        .store()
        .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
            mint.clone(),
            mint.claimed_at(),
            1,
        )?)
        .await?;
    let ready = database
        .store()
        .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::deliverable(
            &mint,
            fixture.protected(),
            mint.claimed_at(),
        )?)
        .await?;
    assert_eq!(ready.state(), GithubRuntimeAuthorityState::Ready);
    assert!(
        database
            .store()
            .load_ready_github_runtime_authority(LoadGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(50),
            )?)
            .await?
            .is_some()
    );
    assert!(
        sqlx::query(
            r"
            UPDATE github_runtime_authority_issuances
            SET ciphertext = set_byte(ciphertext, 0, 1)
            WHERE attempt_id = $1 AND fencing_token = 7
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .execute(database.pool())
        .await
        .is_err()
    );
    Ok(())
}

async fn supersede_ready_authority(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
) -> TestResult {
    let now = database_now(database).await?;
    sqlx::query(
        r"
        UPDATE job_attempts
        SET fencing_token = 8,
            lease_id = $2,
            lease_issued_at_ms = $3,
            lease_expires_at_ms = $4,
            changed_at_ms = $3
        WHERE id = $1
        ",
    )
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .bind(Uuid::new_v4())
    .bind(now.get())
    .bind(now.get() + 300_000)
    .execute(database.pool())
    .await?;
    assert!(
        database
            .store()
            .load_ready_github_runtime_authority(LoadGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(61),
            )?)
            .await?
            .is_none()
    );
    let report = database
        .store()
        .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
            fixture.at(61),
            16,
        )?)
        .await?;
    assert_eq!(report.ready_marked_revoke_pending(), 1);
    Ok(())
}

async fn race_retry_and_confirm_revocation(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
) -> TestResult {
    let left_store = database.store().clone();
    let right_store = database.store().clone();
    let (left, right) = tokio::join!(
        left_store.claim_github_runtime_authority_revocation(revocation_claim(
            AuthorityFixture::owner(301),
            5_000
        )?,),
        right_store.claim_github_runtime_authority_revocation(revocation_claim(
            AuthorityFixture::owner(302),
            5_000
        )?,)
    );
    let mut winners = [left?, right?].into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(winners.len(), 1);
    let first_revoke = winners.pop().expect("one revoker");
    let retried = database
        .store()
        .retry_github_runtime_authority_revocation(RetryGithubRuntimeAuthorityRevocation::new(
            &first_revoke,
            GithubRuntimeAuthorityRevocationFailure::new("provider_unauthorized")?,
            first_revoke.claimed_at(),
            UnixMillis::new(first_revoke.claimed_at().get() + 25),
        )?)
        .await?;
    assert_eq!(retried.state(), GithubRuntimeAuthorityState::RevokePending);
    let retry_evidence = operation_receipt_snapshot(
        database,
        fixture,
        "revocation_outcome",
        i64::try_from(first_revoke.fence().get())?,
    )
    .await?;
    assert_eq!(retry_evidence.0, "applied");
    assert_eq!(retry_evidence.2, "revoke_pending");
    tokio::time::sleep(Duration::from_millis(40)).await;

    let second_revoke = database
        .store()
        .claim_github_runtime_authority_revocation(revocation_claim(
            AuthorityFixture::owner(303),
            5_000,
        )?)
        .await?
        .expect("retry revoker");
    assert!(second_revoke.fence() > first_revoke.fence());
    let terminal = database
        .store()
        .confirm_github_runtime_authority_revocation(
            ConfirmGithubRuntimeAuthorityRevocation::provider_no_content(
                &second_revoke,
                second_revoke.claimed_at(),
            )?,
        )
        .await?;
    assert_eq!(terminal.state(), GithubRuntimeAuthorityState::Revoked);
    assert_eq!(
        terminal.terminal_reason(),
        Some(GithubRuntimeAuthorityTerminalReason::ProviderRevocationConfirmed)
    );
    let erased: (Option<Vec<u8>>, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        r"
        SELECT ciphertext, wrapped_data_key, wrapping_key_id
        FROM github_runtime_authority_issuances
        WHERE attempt_id = $1 AND fencing_token = 7
        ",
    )
    .bind(fixture.identity.key().attempt_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert!(erased.0.is_none() && erased.1.is_none() && erased.2.is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_installs_and_retains_the_exact_v5_gate() -> TestResult {
    run_with_database(|database| async move {
        require_postgres_18(&database).await?;

        let table: Option<String> = sqlx::query_scalar(
            "SELECT pg_catalog.to_regclass('github_runtime_authority_issuances')::TEXT",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(table.as_deref(), Some("github_runtime_authority_issuances"));

        let constraint: String = sqlx::query_scalar(
            r"
            SELECT pg_catalog.pg_get_constraintdef(catalog_constraint.oid)
            FROM pg_catalog.pg_constraint AS catalog_constraint
            WHERE catalog_constraint.conname = 'github_runtime_authority_current_job_ir_v5'
              AND catalog_constraint.conrelid =
                    'github_runtime_authority_issuances'::REGCLASS
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(constraint.contains("job_ir_schema = 5"));

        let row_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_runtime_authority_issuances")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(row_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn mint_begin_persists_and_db_authorizes_the_exact_provider_window() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, 2_000_000_000_000).await?;
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(
                fixture.claim_for(AuthorityFixture::owner(490), 5_000),
            )
            .await?
            .expect("mint claim");

        let too_slow =
            BeginGithubRuntimeAuthorityMint::new(mint.clone(), mint.claimed_at(), 5_001)?;
        assert!(matches!(
            database
                .store()
                .begin_github_runtime_authority_mint(too_slow)
                .await,
            Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
        ));
        let rejected: (String, Option<i64>, Option<i64>, i64) = sqlx::query_as(
            r"
            SELECT authority.state, authority.mint_started_at_ms,
                   authority.mint_provider_request_millis,
                   (SELECT count(*)
                    FROM github_runtime_authority_mint_begins AS begin_evidence
                    WHERE begin_evidence.attempt_id = authority.attempt_id
                      AND begin_evidence.fencing_token = authority.fencing_token
                      AND begin_evidence.claim_fence = authority.mint_claim_fence)
            FROM github_runtime_authority_issuances AS authority
            WHERE authority.attempt_id = $1 AND authority.fencing_token = 7
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(rejected, ("claimed".into(), None, None, 0));

        let exact = BeginGithubRuntimeAuthorityMint::new(mint.clone(), mint.claimed_at(), 4_000)?;
        assert!(matches!(
            database
                .store()
                .begin_github_runtime_authority_mint(exact.clone())
                .await?,
            BeginGithubRuntimeAuthorityMintOutcome::Started(_)
        ));
        assert!(matches!(
            database
                .store()
                .begin_github_runtime_authority_mint(exact)
                .await?,
            BeginGithubRuntimeAuthorityMintOutcome::AlreadyStarted(_)
        ));
        assert!(matches!(
            database
                .store()
                .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                    mint,
                    fixture.identity.requested_at(),
                    3_999,
                )?,)
                .await,
            Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
        ));
        let persisted: (String, i64, i64) = sqlx::query_as(
            r"
            SELECT authority.state, authority.mint_provider_request_millis,
                   count(begin_evidence.*)
            FROM github_runtime_authority_issuances AS authority
            JOIN github_runtime_authority_mint_begins AS begin_evidence
              ON begin_evidence.attempt_id = authority.attempt_id
             AND begin_evidence.fencing_token = authority.fencing_token
             AND begin_evidence.claim_fence = authority.mint_claim_fence
             AND begin_evidence.provider_request_millis =
                 authority.mint_provider_request_millis
            WHERE authority.attempt_id = $1 AND authority.fencing_token = 7
            GROUP BY authority.state, authority.mint_provider_request_millis
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(persisted, ("minting".into(), 4_000, 1));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18, AUTOMATA_TEST_DATABASE_URL, and the JobIR-v5 schema cutover"]
async fn thirty_two_callers_have_one_mint_winner_and_no_post_mint_takeover() -> TestResult {
    run_with_database(|database| async move {
        let contention_fixture = seed_authority(&database).await?;
        claim_single_mint_winner(&database, &contention_fixture).await?;
        assert_pre_mint_terminal_transitions_rejected(&database, &contention_fixture).await?;

        // Keep the 32-way lock queue independent of the deliberately short
        // expiry boundary below. Hosted PostgreSQL can legitimately take more
        // than three seconds to serve every contender under checkpoint load.
        let expiry_fixture = seed_authority(&database).await?;
        let stale_claim = database
            .store()
            .claim_github_runtime_authority_mint(expiry_fixture.claim_for_at(
                AuthorityFixture::owner(199),
                database_now(&database).await?,
                3_000,
            ))
            .await?
            .expect("initial short claim");
        let reclaimed = reclaim_and_begin_mint(&database, &expiry_fixture, stale_claim).await?;
        assert_indeterminate_expiry(&database, &expiry_fixture, &reclaimed).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18, AUTOMATA_TEST_DATABASE_URL, and the JobIR-v5 schema cutover"]
async fn fence_race_two_revokers_retry_and_confirmed_erasure_are_exact() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        mint_ready_authority(&database, &fixture).await?;
        supersede_ready_authority(&database, &fixture).await?;
        race_retry_and_confirm_revocation(&database, &fixture).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18, AUTOMATA_TEST_DATABASE_URL, and the JobIR-v5 schema cutover"]
async fn a_pre_mint_terminal_row_never_replays_as_an_already_started_mint() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(500),
                20,
                100,
            ))
            .await?
            .expect("claim");

        let now = database_now(&database).await?;
        sqlx::query(
            r"
            UPDATE job_attempts
            SET fencing_token = 8,
                lease_id = $2,
                lease_issued_at_ms = $3,
                lease_expires_at_ms = $4,
                changed_at_ms = $3
            WHERE id = $1
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .bind(Uuid::new_v4())
        .bind(now.get())
        .bind(now.get() + 300_000)
        .execute(database.pool())
        .await?;
        let report = database
            .store()
            .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
                fixture.at(40),
                16,
            )?)
            .await?;
        assert_eq!(report.revoked_before_mint(), 1);

        let mint_claimed_at = mint.claimed_at();
        let begin = BeginGithubRuntimeAuthorityMint::new(mint, mint_claimed_at, 1)?;
        assert!(matches!(
            database
                .store()
                .begin_github_runtime_authority_mint(begin)
                .await,
            Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18, AUTOMATA_TEST_DATABASE_URL, and the JobIR-v5 schema cutover"]
async fn stale_commit_is_never_ready_and_cannot_be_erased_before_provider_expiry() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let owner = AuthorityFixture::owner(400);
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(owner, 20, 100))
            .await?
            .expect("claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                mint.clone(),
                mint.claimed_at(),
                1,
            )?)
            .await?;
        let now = database_now(&database).await?;
        sqlx::query(
            r"
            UPDATE job_attempts
            SET fencing_token = 8,
                lease_id = $2,
                lease_issued_at_ms = $3,
                lease_expires_at_ms = $4,
                changed_at_ms = $3
            WHERE id = $1
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .bind(Uuid::new_v4())
        .bind(now.get())
        .bind(now.get() + 300_000)
        .execute(database.pool())
        .await?;
        let committed = database
            .store()
            .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::deliverable(
                &mint,
                fixture.protected(),
                mint.claimed_at(),
            )?)
            .await?;
        assert_eq!(
            committed.state(),
            GithubRuntimeAuthorityState::RevokePending
        );

        let report = database
            .store()
            .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
                fixture.at(3_620_000),
                16,
            )?)
            .await?;
        assert_eq!(report.expired_envelopes_erased(), 0);
        let durable: (String, Option<String>, bool) = sqlx::query_as(
            r"
            SELECT state, terminal_reason, ciphertext IS NOT NULL
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = 7
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable, ("revoke_pending".into(), None, true));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn database_time_authenticates_unprotected_erasure_and_terminal_first_mint_replay()
-> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, 2_000_000_000_000).await?;
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(410),
                20,
                100,
            ))
            .await?
            .expect("mint claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                mint.clone(),
                mint.claimed_at(),
                1,
            )?)
            .await?;
        let authenticate = AuthenticateGithubRuntimeAuthorityUnprotectedErasure::new(&mint);
        let horizon = fixture.identity.conservative_expiry().get();
        set_database_test_clock(&database, horizon - 1).await?;
        assert_eq!(
            database
                .store()
                .authenticate_github_runtime_authority_unprotected_erasure(authenticate.clone())
                .await?,
            None,
            "caller custody is not erasable before locked PostgreSQL time reaches the horizon"
        );

        set_database_test_clock(&database, horizon).await?;
        let terminal = database
            .store()
            .authenticate_github_runtime_authority_unprotected_erasure(authenticate.clone())
            .await?
            .expect("database-authenticated terminal erasure");
        assert_eq!(terminal.state(), GithubRuntimeAuthorityState::Revoked);
        assert_eq!(
            terminal.terminal_reason(),
            Some(GithubRuntimeAuthorityTerminalReason::IndeterminateAuthorityExpired)
        );
        assert_eq!(
            database
                .store()
                .authenticate_github_runtime_authority_unprotected_erasure(authenticate)
                .await?,
            Some(terminal),
            "exact terminal authentication must replay"
        );
        assert_foreign_unprotected_claim_is_rejected(&database, &fixture, &mint).await?;

        let commit = CommitGithubRuntimeAuthority::deliverable(
            &mint,
            fixture.protected(),
            mint.claimed_at(),
        )?;
        assert_eq!(
            database
                .store()
                .commit_github_runtime_authority(&commit)
                .await?,
            terminal,
            "the first post-terminal commit outcome must mint a permanent tombstone"
        );
        assert_eq!(
            database
                .store()
                .commit_github_runtime_authority(&commit)
                .await?,
            terminal
        );
        let receipt = operation_receipt_snapshot(
            &database,
            &fixture,
            "mint_commit",
            i64::try_from(mint.fence().get())?,
        )
        .await?;
        assert_eq!(receipt.0, "terminal_erasable");
        assert_eq!(receipt.1.len(), 32);
        assert_eq!(receipt.2, "revoked");
        assert_eq!(receipt.3, terminal.updated_at().get());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn protected_authority_never_authenticates_unprotected_erasure() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(412),
                20,
                100,
            ))
            .await?
            .expect("mint claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                mint.clone(),
                mint.claimed_at(),
                1,
            )?)
            .await?;
        database
            .store()
            .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::deliverable(
                &mint,
                fixture.protected(),
                mint.claimed_at(),
            )?)
            .await?;
        assert!(matches!(
            database
                .store()
                .authenticate_github_runtime_authority_unprotected_erasure(
                    AuthenticateGithubRuntimeAuthorityUnprotectedErasure::new(&mint),
                )
                .await,
            Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn quarantine_first_observed_after_terminal_erasure_is_permanent() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, 2_100_000_000_000).await?;
        let fixture = seed_authority(&database).await?;
        let protected = fixture.protected();
        mint_ready_authority(&database, &fixture).await?;
        let request = QuarantineGithubRuntimeAuthority::new(
            &protected,
            GithubRuntimeAuthorityCorruptionKind::EnvelopeAuthenticationFailed,
            fixture.at(100),
        )?;
        let safe_erase_after = protected.metadata().safe_erase_after().get();
        set_database_test_clock(&database, safe_erase_after).await?;
        let report = database
            .store()
            .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
                fixture.at(100),
                16,
            )?)
            .await?;
        assert_eq!(report.expired_envelopes_erased(), 1);

        let terminal = database
            .store()
            .quarantine_github_runtime_authority(request)
            .await?;
        assert_eq!(terminal.state(), GithubRuntimeAuthorityState::Revoked);
        assert_eq!(
            database
                .store()
                .quarantine_github_runtime_authority(request)
                .await?,
            terminal
        );
        let disposition: String = sqlx::query_scalar(
            r"
            SELECT disposition
            FROM github_runtime_authority_operation_receipts
            WHERE attempt_id = $1 AND fencing_token = 7
              AND operation_kind = 'quarantine' AND claim_fence = 0
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(disposition, "terminal_erasable");
        Ok(())
    })
    .await
}

#[derive(Clone, Copy)]
enum RunnerAuthorityInvalidation {
    Offline,
    Disabled,
    AdvancedFence,
}

async fn assert_runner_authority_invalidation(
    invalidation: RunnerAuthorityInvalidation,
) -> TestResult {
    run_with_database(move |database| async move {
        let fixture = seed_authority(&database).await?;
        mint_ready_authority(&database, &fixture).await?;
        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fixture.identity.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert!(
            database
                .store()
                .load_ready_github_runtime_authority(LoadGithubRuntimeAuthority::new(
                    fixture.identity.clone(),
                    fixture.at(50),
                )?)
                .await?
                .is_some()
        );

        let statement = match invalidation {
            RunnerAuthorityInvalidation::Offline => {
                "UPDATE runners SET status = 'offline' WHERE id = $1"
            }
            RunnerAuthorityInvalidation::Disabled => {
                "UPDATE runners SET desired_state = 'disabled' WHERE id = $1"
            }
            RunnerAuthorityInvalidation::AdvancedFence => {
                "UPDATE runners SET generation = generation + 1, \
                 session_epoch = session_epoch + 1 WHERE id = $1"
            }
        };
        sqlx::query(statement)
            .bind(fixture.identity.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert!(
            database
                .store()
                .load_ready_github_runtime_authority(LoadGithubRuntimeAuthority::new(
                    fixture.identity.clone(),
                    fixture.at(60),
                )?)
                .await?
                .is_none()
        );
        let report = database
            .store()
            .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
                fixture.at(60),
                16,
            )?)
            .await?;
        assert_eq!(report.ready_marked_revoke_pending(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn runner_authority_requires_online_non_disabled_current_fence() -> TestResult {
    for invalidation in [
        RunnerAuthorityInvalidation::Offline,
        RunnerAuthorityInvalidation::Disabled,
        RunnerAuthorityInvalidation::AdvancedFence,
    ] {
        assert_runner_authority_invalidation(invalidation).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn recovered_indeterminate_token_is_revocation_only() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(600),
                20,
                100,
            ))
            .await?
            .expect("claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                mint.clone(),
                mint.claimed_at(),
                1,
            )?)
            .await?;
        database
            .store()
            .mark_github_runtime_authority_indeterminate(
                MarkGithubRuntimeAuthorityIndeterminate::new(&mint, mint.claimed_at())?,
            )
            .await?;
        let receipt = database
            .store()
            .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::revoke_only(
                &mint,
                fixture.protected(),
                mint.claimed_at(),
            )?)
            .await?;
        assert_eq!(receipt.state(), GithubRuntimeAuthorityState::RevokePending);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn definitive_no_token_retry_is_bounded_single_winner_and_sanitized() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let first = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(1_100),
                20,
                100,
            ))
            .await?
            .expect("first claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                first.clone(),
                first.claimed_at(),
                1,
            )?)
            .await?;
        assert!(matches!(
            RetryGithubRuntimeAuthorityMint::new(
                &first,
                GithubRuntimeAuthorityMintFailure::new("provider_unavailable")?,
                first.claimed_at(),
                UnixMillis::new(first.claimed_at().get() + 120_001),
            ),
            Err(GithubRuntimeAuthorityValueError::InvalidTimeInterval)
        ));

        let retry_observed_at = first.claimed_at();
        let retry_at = UnixMillis::new(retry_observed_at.get() + 5_000);
        let current: bool = sqlx::query_scalar(
            r"
            SELECT automata_github_runtime_authority_is_current(
                authority,
                floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
            )
            FROM github_runtime_authority_issuances AS authority
            WHERE attempt_id = $1 AND fencing_token = 7
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(
            current,
            "minting authority must remain current before retry"
        );
        let retry = RetryGithubRuntimeAuthorityMint::new(
            &first,
            GithubRuntimeAuthorityMintFailure::new("provider_unavailable")?,
            retry_observed_at,
            retry_at,
        )?;
        let pending = database
            .store()
            .retry_github_runtime_authority_mint(retry)
            .await?;
        assert_eq!(
            pending.state(),
            GithubRuntimeAuthorityState::MintRetryPending
        );
        let replay = database
            .store()
            .retry_github_runtime_authority_mint(RetryGithubRuntimeAuthorityMint::new(
                &first,
                GithubRuntimeAuthorityMintFailure::new("provider_unavailable")?,
                retry_observed_at,
                retry_at,
            )?)
            .await?;
        assert_eq!(replay, pending);
        let scheduling_replay = database
            .store()
            .retry_github_runtime_authority_mint(RetryGithubRuntimeAuthorityMint::new(
                &first,
                GithubRuntimeAuthorityMintFailure::new("provider_unavailable")?,
                UnixMillis::new(retry_observed_at.get() + 1),
                UnixMillis::new(retry_at.get() + 1),
            )?)
            .await?;
        assert_eq!(scheduling_replay, pending);

        let inspection = database
            .store()
            .inspect_github_runtime_authority(InspectGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(50),
            )?)
            .await?
            .expect("pending inspection");
        assert_eq!(
            inspection.receipt().state(),
            GithubRuntimeAuthorityState::MintRetryPending
        );
        assert_eq!(inspection.mint_attempts(), 1);
        assert_eq!(
            inspection.next_action_at(),
            Some(UnixMillis::new(pending.updated_at().get() + 5_000))
        );
        assert_eq!(inspection.commit_disposition(), None);
        assert!(!inspection.provider_expiry_known());
        assert_eq!(inspection.safe_erase_after(), None);
        assert_eq!(inspection.corruption(), None);
        assert!(
            sqlx::query(
                "UPDATE github_runtime_authority_issuances \
                 SET mint_attempt_count = 2 \
                 WHERE attempt_id = $1 AND fencing_token = 7",
            )
            .bind(fixture.identity.key().attempt_id().as_uuid())
            .execute(database.pool())
            .await
            .is_err()
        );
        assert!(
            database
                .store()
                .claim_github_runtime_authority_mint(fixture.claim(
                    AuthorityFixture::owner(1_101),
                    59,
                    90,
                ))
                .await?
                .is_none()
        );
        tokio::time::sleep(Duration::from_millis(5_200)).await;

        let mut tasks = Vec::new();
        for ordinal in 0..32_u128 {
            let store = database.store().clone();
            let request = fixture.claim(AuthorityFixture::owner(1_200 + ordinal), 60, 90);
            tasks.push(tokio::spawn(async move {
                store.claim_github_runtime_authority_mint(request).await
            }));
        }
        let mut winners = Vec::new();
        for task in tasks {
            if let Some(claim) = task.await?? {
                winners.push(claim);
            }
        }
        assert_eq!(winners.len(), 1);
        let second = winners.pop().expect("one retry winner");
        assert_eq!(second.attempt(), 2);
        assert!(second.fence() > first.fence());
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                second.clone(),
                second.claimed_at(),
                1,
            )?)
            .await?;

        let rejected = database
            .store()
            .reject_github_runtime_authority_mint(RejectGithubRuntimeAuthorityMint::new(
                &second,
                GithubRuntimeAuthorityMintFailure::new("invalid_installation")?,
                second.claimed_at(),
            )?)
            .await?;
        assert_eq!(rejected.state(), GithubRuntimeAuthorityState::Rejected);
        assert_eq!(
            rejected.terminal_reason(),
            Some(GithubRuntimeAuthorityTerminalReason::ProviderMintRejected)
        );
        let reject_replay = database
            .store()
            .reject_github_runtime_authority_mint(RejectGithubRuntimeAuthorityMint::new(
                &second,
                GithubRuntimeAuthorityMintFailure::new("invalid_installation")?,
                second.claimed_at(),
            )?)
            .await?;
        assert_eq!(reject_replay, rejected);
        assert!(
            database
                .store()
                .claim_github_runtime_authority_mint(fixture.claim(
                    AuthorityFixture::owner(1_300),
                    70,
                    90,
                ))
                .await?
                .is_none()
        );

        let retained = database
            .store()
            .inspect_github_runtime_authority(InspectGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(70),
            )?)
            .await?
            .expect("rejection inspection");
        assert_eq!(retained.receipt(), rejected);
        assert_eq!(retained.mint_attempts(), 2);
        assert_eq!(retained.next_action_at(), None);
        assert!(
            sqlx::query(
                r"
                UPDATE github_runtime_authority_issuances
                SET state = 'claimed', mint_claimed_at_ms = 70,
                    mint_claim_expires_at_ms = 90, mint_started_at_ms = NULL,
                    rejected_at_ms = NULL, terminal_reason = NULL,
                    state_updated_at_ms = 70
                WHERE attempt_id = $1 AND fencing_token = 7
                ",
            )
            .bind(fixture.identity.key().attempt_id().as_uuid())
            .execute(database.pool())
            .await
            .is_err()
        );
        let has_no_protected_columns: bool = sqlx::query_scalar(
            r"
            SELECT provider_expires_at_ms IS NULL
               AND safe_erase_after_ms IS NULL
               AND plaintext_digest IS NULL
               AND aad_digest IS NULL
               AND wrapped_data_key IS NULL
               AND ciphertext IS NULL
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = 7
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(has_no_protected_columns);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn retry_beyond_the_request_deadline_is_a_truthful_terminal_rejection() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(1_400),
                20,
                100,
            ))
            .await?
            .expect("claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                mint.clone(),
                mint.claimed_at(),
                1,
            )?)
            .await?;
        let retry_observed_at = mint.claimed_at();
        let retry_at = UnixMillis::new(retry_observed_at.get() + 120_000);
        let rejected = database
            .store()
            .retry_github_runtime_authority_mint(RetryGithubRuntimeAuthorityMint::new(
                &mint,
                GithubRuntimeAuthorityMintFailure::new("provider_unavailable")?,
                retry_observed_at,
                retry_at,
            )?)
            .await?;
        assert_eq!(rejected.state(), GithubRuntimeAuthorityState::Rejected);
        assert_eq!(
            rejected.terminal_reason(),
            Some(GithubRuntimeAuthorityTerminalReason::ProviderMintRetryExpired)
        );
        assert!(rejected.updated_at() >= mint.claimed_at());
        let replay = database
            .store()
            .retry_github_runtime_authority_mint(RetryGithubRuntimeAuthorityMint::new(
                &mint,
                GithubRuntimeAuthorityMintFailure::new("provider_unavailable")?,
                retry_observed_at,
                retry_at,
            )?)
            .await?;
        assert_eq!(replay, rejected);
        assert!(matches!(
            database
                .store()
                .reject_github_runtime_authority_mint(RejectGithubRuntimeAuthorityMint::new(
                    &mint,
                    GithubRuntimeAuthorityMintFailure::new("provider_unavailable")?,
                    mint.claimed_at(),
                )?)
                .await,
            Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn unknown_provider_expiry_is_revoke_only_and_deferred_to_conservative_erasure() -> TestResult
{
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(1_500),
                20,
                100,
            ))
            .await?
            .expect("claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                mint.clone(),
                mint.claimed_at(),
                1,
            )?)
            .await?;
        assert!(matches!(
            CommitGithubRuntimeAuthority::deliverable(
                &mint,
                fixture.protected_without_provider_expiry(),
                mint.claimed_at(),
            ),
            Err(GithubRuntimeAuthorityValueError::InvalidCommit)
        ));
        let committed = database
            .store()
            .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::revoke_only(
                &mint,
                fixture.protected_without_provider_expiry(),
                mint.claimed_at(),
            )?)
            .await?;
        assert_eq!(
            committed.state(),
            GithubRuntimeAuthorityState::RevokePending
        );
        assert!(
            database
                .store()
                .load_ready_github_runtime_authority(LoadGithubRuntimeAuthority::new(
                    fixture.identity.clone(),
                    fixture.at(50),
                )?)
                .await?
                .is_none()
        );
        let inspection = database
            .store()
            .inspect_github_runtime_authority(InspectGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(50),
            )?)
            .await?
            .expect("revoke-only inspection");
        assert_eq!(
            inspection.commit_disposition(),
            Some(GithubRuntimeAuthorityCommitDisposition::RevokeOnly)
        );
        assert!(!inspection.provider_expiry_known());
        assert_eq!(
            inspection.safe_erase_after(),
            Some(fixture.identity.conservative_expiry())
        );

        let revocation = database
            .store()
            .claim_github_runtime_authority_revocation(revocation_claim(
                AuthorityFixture::owner(1_501),
                5_000,
            )?)
            .await?
            .expect("revocation claim");
        let deferred = database
            .store()
            .defer_github_runtime_authority_revocation(DeferGithubRuntimeAuthorityRevocation::new(
                &revocation,
                GithubRuntimeAuthorityRevocationFailure::new("provider_unauthorized")?,
                revocation.claimed_at(),
            )?)
            .await?;
        assert_eq!(deferred.state(), GithubRuntimeAuthorityState::RevokePending);
        let defer_evidence = operation_receipt_snapshot(
            &database,
            &fixture,
            "revocation_outcome",
            i64::try_from(revocation.fence().get())?,
        )
        .await?;
        assert_eq!(defer_evidence.0, "applied");
        assert_eq!(defer_evidence.2, "revoke_pending");
        assert!(
            database
                .store()
                .claim_github_runtime_authority_revocation(revocation_claim(
                    AuthorityFixture::owner(1_502),
                    5_000
                )?,)
                .await?
                .is_none()
        );
        let deferred_inspection = database
            .store()
            .inspect_github_runtime_authority(InspectGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(100),
            )?)
            .await?
            .expect("deferred inspection");
        assert_eq!(
            deferred_inspection.next_action_at(),
            Some(fixture.identity.conservative_expiry())
        );

        let report = database
            .store()
            .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
                fixture.identity.conservative_expiry(),
                16,
            )?)
            .await?;
        assert_eq!(report.expired_envelopes_erased(), 0);
        let retained = database
            .store()
            .inspect_github_runtime_authority(InspectGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.identity.conservative_expiry(),
            )?)
            .await?
            .expect("retained inspection");
        assert_eq!(
            retained.receipt().state(),
            GithubRuntimeAuthorityState::RevokePending
        );
        assert_eq!(retained.receipt().terminal_reason(), None);
        assert!(!retained.provider_expiry_known());
        let ciphertext: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT ciphertext FROM github_runtime_authority_issuances \
             WHERE attempt_id = $1 AND fencing_token = 7",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(ciphertext.is_some());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn corruption_quarantine_retains_custody_before_the_safe_horizon() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        mint_ready_authority(&database, &fixture).await?;
        let ready = database
            .store()
            .load_ready_github_runtime_authority(LoadGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(50),
            )?)
            .await?
            .expect("ready authority");
        let quarantine = QuarantineGithubRuntimeAuthority::new(
            ready.protected(),
            GithubRuntimeAuthorityCorruptionKind::EnvelopeAuthenticationFailed,
            ready.ready_at(),
        )?;
        let quarantined = database
            .store()
            .quarantine_github_runtime_authority(quarantine)
            .await?;
        assert_eq!(
            quarantined.state(),
            GithubRuntimeAuthorityState::Quarantined
        );
        assert_eq!(
            database
                .store()
                .quarantine_github_runtime_authority(quarantine)
                .await?,
            quarantined
        );
        let mismatched_kind = QuarantineGithubRuntimeAuthority::new(
            ready.protected(),
            GithubRuntimeAuthorityCorruptionKind::RetiredWrappingKey,
            ready.ready_at(),
        )?;
        assert!(matches!(
            database
                .store()
                .quarantine_github_runtime_authority(mismatched_kind)
                .await,
            Err(GithubRuntimeAuthorityStoreError::QuarantineRejected)
        ));
        assert!(
            database
                .store()
                .load_ready_github_runtime_authority(LoadGithubRuntimeAuthority::new(
                    fixture.identity.clone(),
                    fixture.at(61),
                )?)
                .await?
                .is_none()
        );
        assert!(
            database
                .store()
                .claim_github_runtime_authority_revocation(revocation_claim(
                    AuthorityFixture::owner(1_600),
                    5_000
                )?,)
                .await?
                .is_none()
        );
        let inspection = database
            .store()
            .inspect_github_runtime_authority(InspectGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(61),
            )?)
            .await?
            .expect("quarantine inspection");
        assert_eq!(
            inspection.corruption(),
            Some(GithubRuntimeAuthorityCorruptionKind::EnvelopeAuthenticationFailed)
        );
        assert_eq!(
            inspection.commit_disposition(),
            Some(GithubRuntimeAuthorityCommitDisposition::Deliverable)
        );
        assert!(inspection.provider_expiry_known());
        assert_eq!(inspection.safe_erase_after(), Some(fixture.at(3_620_000)));

        let before = database
            .store()
            .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
                fixture.at(3_619_999),
                16,
            )?)
            .await?;
        assert_eq!(before.quarantined_envelopes_erased(), 0);
        let caller_horizon = database
            .store()
            .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
                fixture.at(3_620_000),
                16,
            )?)
            .await?;
        assert_eq!(caller_horizon.quarantined_envelopes_erased(), 0);
        let retained = database
            .store()
            .inspect_github_runtime_authority(InspectGithubRuntimeAuthority::new(
                fixture.identity.clone(),
                fixture.at(3_620_000),
            )?)
            .await?
            .expect("quarantine inspection");
        assert_eq!(
            retained.receipt().state(),
            GithubRuntimeAuthorityState::Quarantined
        );
        assert_eq!(retained.receipt().terminal_reason(), None);
        assert_eq!(
            retained.corruption(),
            Some(GithubRuntimeAuthorityCorruptionKind::EnvelopeAuthenticationFailed)
        );
        let erased: (Option<Vec<u8>>, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
            r"
            SELECT ciphertext, wrapped_data_key, quarantine_kind
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = 7
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(erased.0.is_some() && erased.1.is_some());
        assert_eq!(erased.2.as_deref(), Some("envelope_authentication_failed"));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn operation_receipts_require_reciprocal_transitions_and_are_fully_immutable() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(1_680),
                20,
                100,
            ))
            .await?
            .expect("mint claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                mint.clone(),
                mint.claimed_at(),
                1,
            )?)
            .await?;
        assert_forged_mint_receipt_rejected(&database, &fixture, &mint).await?;
        let protected = fixture.protected();
        database
            .store()
            .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::deliverable(
                &mint,
                fixture.protected(),
                mint.claimed_at(),
            )?)
            .await?;

        assert_forged_quarantine_receipt_rejected(&database, &fixture).await?;
        supersede_ready_authority(&database, &fixture).await?;
        let revocation = database
            .store()
            .claim_github_runtime_authority_revocation(revocation_claim(
                AuthorityFixture::owner(1_681),
                5_000,
            )?)
            .await?
            .expect("revocation claim");
        assert_forged_revocation_receipt_rejected(&database, &fixture, &revocation).await?;
        assert_quarantine_transition_requires_receipt(&database, &fixture).await?;

        let quarantine = QuarantineGithubRuntimeAuthority::new(
            &protected,
            GithubRuntimeAuthorityCorruptionKind::InvalidEnvelope,
            fixture.at(100),
        )?;
        database
            .store()
            .quarantine_github_runtime_authority(quarantine)
            .await?;
        let reciprocal: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*)
                 FROM github_runtime_authority_operation_transitions
                 WHERE attempt_id = $1 AND fencing_token = 7
                   AND operation_kind = 'quarantine'),
                (SELECT count(*)
                 FROM github_runtime_authority_operation_receipts
                 WHERE attempt_id = $1 AND fencing_token = 7
                   AND operation_kind = 'quarantine')
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(reciprocal, (1, 1));
        assert_operation_evidence_is_immutable(&database).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(
    clippy::too_many_lines,
    reason = "one atomic replay scenario proves pre-terminal conflicts, terminal replay, and receipt retention"
)]
async fn commit_replay_requires_identical_time_disposition_metadata_and_envelope_bytes()
-> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        let mint = database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(1_700),
                20,
                100,
            ))
            .await?
            .expect("claim");
        database
            .store()
            .begin_github_runtime_authority_mint(BeginGithubRuntimeAuthorityMint::new(
                mint.clone(),
                mint.claimed_at(),
                1,
            )?)
            .await?;
        assert!(matches!(
            CommitGithubRuntimeAuthority::deliverable(
                &mint,
                fixture.protected_with_expiry(Some(fixture.at(50_000)), 0x61, 0x62, 0x63, 0x64,),
                mint.claimed_at(),
            ),
            Err(GithubRuntimeAuthorityValueError::InvalidCommit)
        ));
        let commit = CommitGithubRuntimeAuthority::deliverable(
            &mint,
            fixture.protected(),
            mint.claimed_at(),
        )?;
        let committed = database
            .store()
            .commit_github_runtime_authority(&commit)
            .await?;
        assert_eq!(committed.state(), GithubRuntimeAuthorityState::Ready);
        let applied_evidence = operation_receipt_snapshot(
            &database,
            &fixture,
            "mint_commit",
            i64::try_from(mint.fence().get())?,
        )
        .await?;
        assert_eq!(applied_evidence.0, "applied");
        assert_eq!(applied_evidence.1.len(), 32);
        assert_eq!(applied_evidence.2, "ready");
        assert_eq!(applied_evidence.3, committed.updated_at().get());
        let exact_replay = database
            .store()
            .commit_github_runtime_authority(&commit)
            .await?;
        assert_eq!(exact_replay, committed);

        let changed_ciphertext =
            fixture.protected_with_expiry(Some(fixture.at(3_500_000)), 0x61, 0x62, 0x63, 0x65);
        assert!(matches!(
            database
                .store()
                .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::deliverable(
                    &mint,
                    changed_ciphertext,
                    mint.claimed_at(),
                )?)
                .await,
            Err(GithubRuntimeAuthorityStoreError::IdentityConflict)
        ));
        assert!(matches!(
            database
                .store()
                .commit_github_runtime_authority(&CommitGithubRuntimeAuthority::deliverable(
                    &mint,
                    fixture.protected(),
                    UnixMillis::new(mint.claimed_at().get() + 1),
                )?)
                .await,
            Err(GithubRuntimeAuthorityStoreError::IdentityConflict)
        ));
        assert!(
            sqlx::query(
                "UPDATE github_runtime_authority_issuances \
                 SET commit_disposition = 'revoke_only' \
                 WHERE attempt_id = $1 AND fencing_token = 7",
            )
            .bind(fixture.identity.key().attempt_id().as_uuid())
            .execute(database.pool())
            .await
            .is_err()
        );

        supersede_ready_authority(&database, &fixture).await?;
        let revocation = database
            .store()
            .claim_github_runtime_authority_revocation(revocation_claim(
                AuthorityFixture::owner(1_701),
                5_000,
            )?)
            .await?
            .expect("revocation claim");
        let terminal = database
            .store()
            .confirm_github_runtime_authority_revocation(
                ConfirmGithubRuntimeAuthorityRevocation::provider_no_content(
                    &revocation,
                    revocation.claimed_at(),
                )?,
            )
            .await?;
        assert_eq!(terminal.state(), GithubRuntimeAuthorityState::Revoked);
        assert_eq!(
            database
                .store()
                .commit_github_runtime_authority(&commit)
                .await?,
            committed,
            "terminal state must not rewrite an exact commit replay snapshot"
        );
        database
            .store()
            .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
                fixture.at(3_620_000),
                16,
            )?)
            .await?;
        let retained_evidence = operation_receipt_snapshot(
            &database,
            &fixture,
            "mint_commit",
            i64::try_from(mint.fence().get())?,
        )
        .await?;
        assert_eq!(
            retained_evidence, applied_evidence,
            "reconciliation must retain the exact digest and result snapshot permanently"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn permanent_terminal_replay_precedes_mutable_issuance_and_graph_locks() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        mint_ready_authority(&database, &fixture).await?;
        supersede_ready_authority(&database, &fixture).await?;
        let revocation = database
            .store()
            .claim_github_runtime_authority_revocation(revocation_claim(
                AuthorityFixture::owner(1_750),
                5_000,
            )?)
            .await?
            .expect("revocation claim");
        let confirm = ConfirmGithubRuntimeAuthorityRevocation::provider_no_content(
            &revocation,
            revocation.claimed_at(),
        )?;
        let terminal = database
            .store()
            .confirm_github_runtime_authority_revocation(confirm)
            .await?;
        assert_eq!(terminal.state(), GithubRuntimeAuthorityState::Revoked);

        for lock_sql in [
            "SELECT attempt_id FROM github_runtime_authority_issuances \
             WHERE attempt_id = $1 AND fencing_token = 7 FOR UPDATE",
            "SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE",
        ] {
            let mut blocker = database.pool().begin().await?;
            let locked = sqlx::query(lock_sql)
                .bind(fixture.identity.key().attempt_id().as_uuid())
                .fetch_all(&mut *blocker)
                .await?;
            assert_eq!(locked.len(), 1, "mutable lock fixture must select one row");

            let store = database.store().clone();
            let mut replay = tokio::spawn(async move {
                store
                    .confirm_github_runtime_authority_revocation(confirm)
                    .await
            });
            let replay_result = tokio::time::timeout(Duration::from_millis(500), &mut replay).await;
            blocker.rollback().await?;
            let Ok(joined) = replay_result else {
                replay.await??;
                return Err("permanent replay waited for a mutable issuance or graph lock".into());
            };
            let replayed = joined??;
            assert_eq!(replayed, terminal);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn lease_extension_invalidates_without_mutating_authority_horizons() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        mint_ready_authority(&database, &fixture).await?;
        let extended_lease_expires_at = fixture.identity.lease_expires_at().get() + 60_000;
        let now = database_now(&database).await?;
        sqlx::query(
            r"
            UPDATE job_attempts
            SET lease_expires_at_ms = $2, changed_at_ms = $3
            WHERE id = $1 AND fencing_token = 7
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .bind(extended_lease_expires_at)
        .bind(now.get())
        .execute(database.pool())
        .await?;
        assert!(
            database
                .store()
                .load_ready_github_runtime_authority(LoadGithubRuntimeAuthority::new(
                    fixture.identity.clone(),
                    fixture.at(50),
                )?)
                .await?
                .is_none()
        );
        let immutable_authority_lease: i64 = sqlx::query_scalar(
            "SELECT lease_expires_at_ms FROM github_runtime_authority_issuances \
             WHERE attempt_id = $1 AND fencing_token = 7",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            immutable_authority_lease,
            fixture.identity.lease_expires_at().get()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn inspection_requires_exact_provider_identity_and_direct_lifecycle_edits_fail() -> TestResult
{
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(1_800),
                20,
                100,
            ))
            .await?
            .expect("claim");
        for mismatched in [
            identity_with_provider(&fixture.identity, 0xbeef, 9_001)?,
            identity_with_provider(&fixture.identity, 0xfeed, 9_002)?,
        ] {
            assert!(matches!(
                database
                    .store()
                    .inspect_github_runtime_authority(InspectGithubRuntimeAuthority::new(
                        mismatched,
                        fixture.at(30),
                    )?)
                    .await,
                Err(GithubRuntimeAuthorityStoreError::IdentityConflict)
            ));
        }
        for statement in [
            "UPDATE github_runtime_authority_issuances \
             SET provider_connection_id = '00000000-0000-0000-0000-00000000beef'",
            "UPDATE github_runtime_authority_issuances SET provider_installation_id = 9002",
            "UPDATE github_runtime_authority_issuances SET state = 'quarantined'",
        ] {
            assert!(
                sqlx::query(statement)
                    .execute(database.pool())
                    .await
                    .is_err()
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn one_worker_concurrently_creates_only_one_revocation_claim() -> TestResult {
    run_with_database(|database| async move {
        let first = seed_authority(&database).await?;
        let second = seed_authority(&database).await?;
        for fixture in [&first, &second] {
            mint_ready_authority(&database, fixture).await?;
            supersede_ready_authority(&database, fixture).await?;
        }
        let owner = AuthorityFixture::owner(700);
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.claim_github_runtime_authority_revocation(revocation_claim(owner, 5_000)?,),
            right_store.claim_github_runtime_authority_revocation(revocation_claim(owner, 5_000)?,)
        );
        let claims = [left?, right?].into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(claims.len(), 1);
        let active_claim_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_runtime_authority_issuances \
             WHERE revoke_claim_owner_id = $1",
        )
        .bind(owner.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(active_claim_count, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn every_expired_takeover_consumes_budget_and_releases_exhausted_owner() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, 2_200_000_000_000).await?;
        let first = seed_authority(&database).await?;
        let second = seed_authority(&database).await?;
        for fixture in [&first, &second] {
            mint_ready_authority(&database, fixture).await?;
            supersede_ready_authority(&database, fixture).await?;
        }
        let owner = AuthorityFixture::owner(800);
        let initial = database
            .store()
            .claim_github_runtime_authority_revocation(revocation_claim(owner, 250)?)
            .await?
            .expect("initial claim");
        let exhausted_key = initial.key();
        let mut next_takeover_at = initial.expires_at().get();
        for expected_attempt in 2..=64_u16 {
            set_database_test_clock(&database, next_takeover_at).await?;
            let claim = database
                .store()
                .claim_github_runtime_authority_revocation(revocation_claim(owner, 250)?)
                .await?
                .expect("takeover claim");
            assert_eq!(claim.key(), exhausted_key);
            assert_eq!(claim.attempt(), expected_attempt);
            next_takeover_at = claim.expires_at().get();
        }

        set_database_test_clock(&database, next_takeover_at).await?;
        let next = database
            .store()
            .claim_github_runtime_authority_revocation(revocation_claim(owner, 5_000)?)
            .await?
            .expect("next authority after exhausted claim");
        assert_ne!(next.key(), exhausted_key);
        assert_eq!(next.attempt(), 1);
        let exhausted: (i16, Option<Uuid>, Option<String>) = sqlx::query_as(
            r"
            SELECT revoke_attempt_count, revoke_claim_owner_id,
                   last_revoke_failure_kind
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(exhausted_key.attempt_id().as_uuid())
        .bind(i64::try_from(exhausted_key.fencing_token().get())?)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(exhausted, (64, None, Some("claim_budget_exhausted".into())));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn stale_revocation_mutations_cannot_cross_a_takeover_fence() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        mint_ready_authority(&database, &fixture).await?;
        supersede_ready_authority(&database, &fixture).await?;
        let first = database
            .store()
            .claim_github_runtime_authority_revocation(revocation_claim(
                AuthorityFixture::owner(900),
                2_000,
            )?)
            .await?
            .expect("first claim");
        let late_retry = RetryGithubRuntimeAuthorityRevocation::new(
            &first,
            GithubRuntimeAuthorityRevocationFailure::new("late_retry")?,
            first.claimed_at(),
            UnixMillis::new(first.claimed_at().get() + 20),
        )?;
        tokio::time::sleep(Duration::from_millis(2_100)).await;
        let second = database
            .store()
            .claim_github_runtime_authority_revocation(revocation_claim(
                AuthorityFixture::owner(901),
                5_000,
            )?)
            .await?
            .expect("takeover claim");
        assert!(second.fence() > first.fence());
        let expired_receipt = database
            .store()
            .retry_github_runtime_authority_revocation(late_retry.clone())
            .await?;
        assert_eq!(
            expired_receipt.state(),
            GithubRuntimeAuthorityState::RevokePending
        );
        assert_eq!(
            database
                .store()
                .retry_github_runtime_authority_revocation(late_retry.clone())
                .await?,
            expired_receipt,
            "the first old-fence outcome after takeover must replay permanently"
        );
        let conflicting_retry = RetryGithubRuntimeAuthorityRevocation::new(
            &first,
            GithubRuntimeAuthorityRevocationFailure::new("conflicting_retry")?,
            first.claimed_at(),
            UnixMillis::new(first.claimed_at().get() + 20),
        )?;
        assert!(matches!(
            database
                .store()
                .retry_github_runtime_authority_revocation(conflicting_retry)
                .await,
            Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
        ));
        assert_eq!(
            database
                .store()
                .retry_github_runtime_authority_revocation(late_retry)
                .await?,
            expired_receipt,
            "the later live fence must not erase the first fence's exact replay"
        );
        let stale_confirm = ConfirmGithubRuntimeAuthorityRevocation::provider_no_content(
            &first,
            first.claimed_at(),
        )?;
        assert!(matches!(
            database
                .store()
                .confirm_github_runtime_authority_revocation(stale_confirm)
                .await,
            Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
        ));
        let still_protected: (String, bool) = sqlx::query_as(
            r"
            SELECT state, ciphertext IS NOT NULL
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = 7
            ",
        )
        .bind(fixture.identity.key().attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(still_protected, ("revoke_pending".into(), true));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn audit_identity_cannot_be_updated_deleted_or_truncated() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        database
            .store()
            .claim_github_runtime_authority_mint(fixture.claim(
                AuthorityFixture::owner(1_000),
                20,
                100,
            ))
            .await?
            .expect("claim");
        for statement in [
            "UPDATE github_runtime_authority_issuances \
             SET authority_namespace = 'changed'",
            "DELETE FROM github_runtime_authority_issuances",
            "TRUNCATE github_runtime_authority_issuances",
            "UPDATE github_runtime_authority_mint_claims SET claimed_at_ms = claimed_at_ms",
            "DELETE FROM github_runtime_authority_mint_claims",
            "TRUNCATE github_runtime_authority_mint_claims",
        ] {
            assert!(
                sqlx::query(statement)
                    .execute(database.pool())
                    .await
                    .is_err()
            );
        }
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_runtime_authority_issuances")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(rows, 1);
        let claims: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_runtime_authority_mint_claims")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(claims, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn ready_authority_caps_renewal_and_revalidates_it_atomically() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_authority(&database).await?;
        mint_ready_authority(&database, &fixture).await?;
        let request = assert_ready_renewal_ceiling(&database, &fixture).await?;
        assert_authority_boundary_rejections(&database, &fixture, request).await?;
        assert_authority_transition_race(&database, &fixture, request).await?;
        Ok(())
    })
    .await
}

fn renewal_request(
    identity: &GithubRuntimeAuthorityIdentity,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> TestResult<RenewLease> {
    Ok(RenewLease::new(
        identity.key().attempt_id(),
        automata_ci_store::RunnerSessionFence::new(
            identity.runner_session_id(),
            identity.runner_id(),
            identity.runner_generation(),
            identity.runner_session_epoch(),
        ),
        automata_ci_core::LeaseGuard::new(identity.lease_id(), identity.key().fencing_token()),
        observed_at,
        expires_at,
    )?)
}

async fn assert_ready_renewal_ceiling(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
) -> TestResult<RenewLease> {
    let request = renewal_request(
        &fixture.identity,
        database_now(database).await?,
        fixture.at(3_490_000),
    )?;
    let bounded = database
        .store()
        .authorize_lease_renewal(request, JobLifecycle::Running)
        .await?;
    assert_eq!(bounded.expires_at(), fixture.at(3_440_000));
    assert_eq!(
        database.store().renew_lease(bounded).await?.expires_at(),
        fixture.at(3_440_000)
    );
    let first_changed_at: i64 =
        sqlx::query_scalar("SELECT changed_at_ms FROM job_attempts WHERE id = $1")
            .bind(request.attempt_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
    let capped_again = database
        .store()
        .authorize_lease_renewal(
            renewal_request(
                &fixture.identity,
                database_now(database).await?,
                fixture.at(3_500_000),
            )?,
            JobLifecycle::Running,
        )
        .await?;
    assert_eq!(capped_again.expires_at(), fixture.at(3_440_000));
    database.store().renew_lease(capped_again).await?;
    let changed_at: i64 =
        sqlx::query_scalar("SELECT changed_at_ms FROM job_attempts WHERE id = $1")
            .bind(request.attempt_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(
        changed_at, first_changed_at,
        "ceiling replay must not forge an extension"
    );
    Ok(request)
}

async fn assert_authority_boundary_rejections(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
    request: RenewLease,
) -> TestResult {
    let oversized = renewal_request(
        &fixture.identity,
        database_now(database).await?,
        fixture.at(3_450_000),
    )?;
    let oversized_result = database.store().renew_lease(oversized).await;
    assert_eq!(
        oversized_result?.expires_at(),
        fixture.at(3_440_000),
        "the one-step renewal path must apply the same authority ceiling"
    );
    let wrong_observed_at = database_now(database).await?;
    let wrong_session = RenewLease::new(
        request.attempt_id(),
        automata_ci_store::RunnerSessionFence::new(
            automata_ci_core::RunnerSessionId::new(),
            fixture.identity.runner_id(),
            fixture.identity.runner_generation(),
            fixture.identity.runner_session_epoch(),
        ),
        request.guard(),
        wrong_observed_at,
        UnixMillis::new(wrong_observed_at.get() + 1_000),
    )?;
    let wrong_result = database
        .store()
        .authorize_lease_renewal(wrong_session, JobLifecycle::Running)
        .await;
    assert!(matches!(
        wrong_result,
        Err(StoreError::Attempt(AttemptStoreError::RunnerRejected(attempt_id)))
            if attempt_id == request.attempt_id()
    ));
    Ok(())
}

async fn assert_authority_transition_race(
    database: &TestDatabase,
    fixture: &AuthorityFixture,
    request: RenewLease,
) -> TestResult {
    sqlx::query("UPDATE job_attempts SET lifecycle = 'running' WHERE id = $1")
        .bind(request.attempt_id().as_uuid())
        .execute(database.pool())
        .await?;
    let raced_observed_at = database_now(database).await?;
    let raced = database
        .store()
        .authorize_lease_renewal(
            RenewLease::new(
                request.attempt_id(),
                request.session(),
                request.guard(),
                raced_observed_at,
                UnixMillis::new(raced_observed_at.get() + 1_000),
            )?,
            JobLifecycle::Running,
        )
        .await?;
    sqlx::query("UPDATE runners SET desired_state = 'disabled' WHERE id = $1")
        .bind(fixture.identity.runner_id().as_uuid())
        .execute(database.pool())
        .await?;
    let report = database
        .store()
        .reconcile_github_runtime_authorities(ReconcileGithubRuntimeAuthorities::new(
            database_now(database).await?,
            16,
        )?)
        .await?;
    assert_eq!(report.ready_marked_revoke_pending(), 1);
    sqlx::query("UPDATE runners SET desired_state = 'active' WHERE id = $1")
        .bind(fixture.identity.runner_id().as_uuid())
        .execute(database.pool())
        .await?;
    let raced_result = database.store().renew_lease(raced).await;
    assert!(
        matches!(
            &raced_result,
            Err(AttemptStoreError::RuntimeAuthorityUnavailable(attempt_id))
                if *attempt_id == request.attempt_id()
        ),
        "unexpected raced renewal result: {raced_result:?}"
    );
    let non_ready_observed_at = database_now(database).await?;
    let non_ready_result = database
        .store()
        .authorize_lease_renewal(
            RenewLease::new(
                request.attempt_id(),
                request.session(),
                request.guard(),
                non_ready_observed_at,
                UnixMillis::new(non_ready_observed_at.get() + 1_000),
            )?,
            JobLifecycle::Running,
        )
        .await;
    assert_unavailable(&non_ready_result, request.attempt_id());

    let finalizing = renewal_request(
        &fixture.identity,
        database_now(database).await?,
        fixture.at(3_450_000),
    )?;
    let authorized = database
        .store()
        .authorize_lease_renewal(finalizing, JobLifecycle::Finalizing)
        .await?;
    let finalizing_expires_at = authorized.expires_at();
    let transaction = CommitLeaseHeartbeat::new(
        RunnerOperationRequest::new(
            authorized.session(),
            OperationId::new(),
            RunnerOperationKind::new("automata.runner.lease-heartbeat.v1")?,
            Sha256Digest::from_bytes([0x91; 32]),
        ),
        CommandCursor::initial(),
        authorized,
        RunnerOperationResponse::new(DocumentSchema::new(1)?, b"finalizing".to_vec())?,
    )?
    .with_reported_lifecycle(JobLifecycle::Finalizing)?;
    database.store().commit_lease_heartbeat(transaction).await?;
    let durable: (String, i64) =
        sqlx::query_as("SELECT lifecycle, lease_expires_at_ms FROM job_attempts WHERE id = $1")
            .bind(request.attempt_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(
        durable,
        ("finalizing".to_owned(), finalizing_expires_at.get()),
        "quiescent lifecycle and uncapped renewal must commit atomically"
    );
    Ok(())
}

fn assert_unavailable(result: &Result<RenewLease, StoreError>, expected_attempt_id: AttemptId) {
    assert!(
        matches!(
            result,
            Err(StoreError::Attempt(AttemptStoreError::RuntimeAuthorityUnavailable(attempt_id)))
                if *attempt_id == expected_attempt_id
        ),
        "unexpected unavailable result: {result:?}"
    );
}
