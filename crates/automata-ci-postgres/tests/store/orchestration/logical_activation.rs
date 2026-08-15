use crate::github_manifest_fixture;

use automata_ci_core::{
    JOB_IR_SCHEMA_VERSION, JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, JobAuthorityProfile,
    JobInstanceIdentity, RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId, Sha256Digest, UnixMillis,
    WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation,
    ClaimNextLogicalJobOrchestration, ClaimProviderDelivery, ClaimedLogicalJobActivation,
    ConsumeSelectedLogicalJobOrchestration, ConsumedLogicalJobOrchestrationAuthority,
    EnsureGithubServerServiceAuthority, GithubCheckHeadSha, GithubCheckName,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    JobEnvironmentActivationEvidence, JobEventTrust, JobSourceKind, LogicalActivationObject,
    LogicalActivationPreparationStore as _, LogicalActivationPreparationTarget,
    LogicalActivationRepository as _, LogicalActivationStoreError, LogicalActivationWorkerId,
    LogicalJobOrchestrationSelectionOutcome, LogicalJobSchedulingPolicyScope,
    LogicalWorkSelectionId, LogicalWorkSelectionRepository as _,
    LogicalWorkflowAdmissionRepository as _, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, PublishLogicalJobActivation, RenewLogicalJobActivation,
    ResolvedLogicalJobSchedulingPolicy, ReusableSecretPermission, TenantScope,
    WORKFLOW_ADMISSION_EPOCH, WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};
use uuid::Uuid;

use crate::support::{TestDatabase, TestResult, run_with_database};

struct Fixture {
    tenant: String,
    namespace: u128,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    first_job: LogicalWorkflowJobId,
    second_job: LogicalWorkflowJobId,
}

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Logical activation test tenant', 1, 1)
        ",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

fn admission_object(key: String, digest: u8) -> AdmissionObject {
    admission_object_with_media(key, digest, "application/json")
}

fn admission_object_with_media(key: String, digest: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("object key"),
        768,
        media_type,
    )
    .expect("admission object")
}

fn runtime_context_object(key: String, digest: u8) -> AdmissionObject {
    admission_object_with_media(
        key,
        digest,
        "application/vnd.automata.job-runtime-context.protobuf",
    )
}

fn admission_base_context(namespace: u128) -> AdmissionObject {
    runtime_context_object(format!("activation/{namespace}/base-context.pb"), 4)
}

async fn fixture(database: &TestDatabase, tenant: &str, namespace: u128) -> TestResult<Fixture> {
    let tenant_scope = TenantScope::from_authenticated_tenant_id(tenant)?;
    let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 20))?;
    let installation = ProviderInstallationId::new(u64::try_from(namespace + 30)?)?;
    let github_repository = ProviderRepositoryId::new(u64::try_from(namespace + 40)?)?;
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new(
        tenant_scope.clone(),
        connection,
        installation,
        github_repository,
        GithubRepositoryName::new(format!("sample-owner/sample-{namespace}"))?,
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(u64::try_from(namespace + 50)?)?,
        GithubServerServiceAppClientId::new(format!("Iv1.activation-{namespace}"))?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([7; 32]),
        GithubServerServiceRevision::new(1)?,
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([6; 32]))?,
        GithubServerServiceRevision::new(1)?,
        GithubServerServiceRevision::new(1)?,
        JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI")?,
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1)?,
    );
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("invocation");
    let first_job =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("first job");
    let second_job =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 7)).expect("second job");
    let first = AdmittedLogicalWorkflowJob::new(
        first_job,
        WorkflowJobKey::new("prepare").expect("key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("first job");
    let second = AdmittedLogicalWorkflowJob::new(
        second_job,
        WorkflowJobKey::new("verify").expect("key"),
        1,
        LogicalWorkflowJobKind::Steps,
        vec![first_job],
    )
    .expect("second job");
    let command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!("activation-{namespace}"))
            .expect("idempotency"),
        Sha256Digest::from_bytes([41; 32]),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            github_repository.get().to_string(),
            "sample-owner",
            format!("sample-{namespace}"),
        )
        .expect("repository"),
        workflow_id,
        ".ci/workflows/ci.yml",
        "Verify",
        "refs/heads/main",
        snapshot_id,
        admission_object(format!("activation/{namespace}/source"), 1),
        admission_object_with_media(
            format!("activation/{namespace}/plan-v1"),
            2,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(format!("activation/{namespace}/event"), 3),
        vec![9; 20],
        vec![first, second],
        UnixMillis::new(database_now_ms(database).await?),
    )
    .base_context(admission_base_context(namespace))
    .build()
    .expect("logical workflow fixture");
    Ok(Fixture {
        tenant: tenant.to_owned(),
        namespace,
        manifest,
        command,
        first_job,
        second_job,
    })
}

#[allow(clippy::too_many_lines)] // The fixture stages one complete authenticated delivery transaction.
async fn admit_authenticated_fixture(database: &TestDatabase, fixture: &mut Fixture) -> TestResult {
    let now = UnixMillis::new(database_now_ms(database).await?);
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                fixture.manifest.clone(),
                now,
            ),
        )
        .await?;
    let manifest = &fixture.manifest;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            GithubServerServiceAuthorityIdentity::new(
                manifest.tenant().clone(),
                GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(fixture.namespace + 21))?,
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
                Sha256Digest::from_bytes([11; 32]),
            )?,
            now,
        )?)
        .await?;
    let accepted_at = UnixMillis::new(database_now_ms(database).await?);
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
                    format!("activation-{}", fixture.namespace),
                )?,
                fixture.command.request_digest(),
                crate::support::authenticated_github_event_object(fixture.command.event())?,
                accepted_at,
            )?,
            ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace + 60)?)?,
            ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace + 60)?)?,
            automata_ci_store::GithubAuthenticatedEvent::new(
                automata_ci_store::GithubAuthenticatedEventKind::Push,
                "refs/heads/main",
            )?,
            GithubCheckHeadSha::new([9; 20])?,
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
        )?)
        .await?;
    let claim_observed_at = database_now_ms(database).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(fixture.namespace + 22))?,
            UnixMillis::new(claim_observed_at),
            UnixMillis::new(claim_observed_at + 60_000),
        )?)
        .await?
        .ok_or("accepted GitHub delivery was not claimable")?;
    assert_eq!(claimed.claim().delivery_id(), accepted.delivery_id());
    crate::support::register_provider_delivery_workflow_inventory(
        database,
        &fixture.manifest,
        &fixture.command,
        claimed.claim(),
        claimed.claimed_at(),
    )
    .await?;
    fixture.command = logical_command_at(&fixture.command, claimed.claimed_at())?;
    let authenticated = AuthenticatedGithubDeliveryClaim::new(
        claimed.claim(),
        claimed.attempt(),
        claimed.claimed_at(),
        claimed.expires_at(),
    )?;
    database
        .store()
        .admit_authenticated_github_delivery(
            fixture.command.clone(),
            authenticated,
            fixture.command.admitted_at(),
        )
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

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}

async fn wait_until_database_after(database: &TestDatabase, target_ms: i64) -> TestResult {
    while database_now_ms(database).await? <= target_ms {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(())
}

fn orchestration_selection_request(
    selection: u128,
    owner: u128,
    observed_at: i64,
    duration_ms: i64,
) -> ClaimNextLogicalJobOrchestration {
    ClaimNextLogicalJobOrchestration::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection)).expect("selection"),
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(owner)).expect("owner"),
        UnixMillis::new(observed_at),
        duration_ms,
    )
    .expect("orchestration selection request")
}

async fn consume_orchestration(
    database: &TestDatabase,
    selected: automata_ci_store::SelectedLogicalJobOrchestration,
) -> TestResult<automata_ci_store::ConsumedSelectedLogicalJobOrchestration> {
    Ok(database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?)
}

async fn select_orchestration(
    database: &TestDatabase,
    selection: u128,
    owner: u128,
    duration_ms: i64,
) -> TestResult<automata_ci_store::ConsumedSelectedLogicalJobOrchestration> {
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(orchestration_selection_request(
            selection,
            owner,
            observed_at,
            duration_ms,
        ))
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected orchestration selection, got {outcome:?}").into()),
    };
    consume_orchestration(database, selected).await
}

async fn prepare_job(
    database: &TestDatabase,
    fixture: &Fixture,
    logical_job_id: LogicalWorkflowJobId,
    namespace: u128,
) -> TestResult<automata_ci_store::LogicalActivationPreparationReceipt> {
    let expected_target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        logical_job_id,
    )?;
    let selected = select_orchestration(database, namespace + 800, namespace + 900, 60_000).await?;
    assert_eq!(selected.selected().target(), &expected_target);
    let claimed = match selected.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed.clone(),
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            return Err(format!("expected preparation authority, got {authority:?}").into());
        }
    };
    Ok(database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            claimed.descriptor().clone(),
            claimed.claim().clone(),
            claimed.descriptor().base_context().clone(),
            runtime_context_object(format!("preparation/{namespace}/needs.pb"), 32),
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?)
}

fn instance(
    claimed: &ClaimedLogicalJobActivation,
    index: u32,
    total: u32,
    namespace: u128,
    payload_digest: u8,
) -> ActivatedLogicalInstanceDescriptor {
    let identity = JobInstanceIdentity::new(
        claimed.logical_key().as_str(),
        index,
        total,
        Sha256Digest::from_bytes([u8::try_from(index).unwrap_or(u8::MAX); 32]),
    )
    .expect("matrix identity");
    ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        format!("/workspace/{namespace}/{index}"),
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes([payload_digest; 32]),
            ObjectKey::new(format!(
                "activation/{namespace}/instances/{index}/job-ir.pb"
            ))
            .expect("JobIR key"),
            1_024,
        )
        .expect("JobIR descriptor"),
        LogicalActivationObject::runtime_context(
            Sha256Digest::from_bytes([payload_digest.wrapping_add(1); 32]),
            ObjectKey::new(format!(
                "activation/{namespace}/instances/{index}/runtime-context.pb"
            ))
            .expect("runtime key"),
            512,
        )
        .expect("runtime descriptor"),
        JobEnvironmentActivationEvidence::new(
            None,
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        ),
    )
    .expect("instance descriptor")
}

async fn assert_current_cluster_compatibility(database: &TestDatabase) -> TestResult {
    let compatibility: (i32, i32, i32) = sqlx::query_as(
        r"
        SELECT minimum_admission_epoch, job_ir_schema,
               runner_requirements_schema
        FROM automata_cluster_compatibility WHERE singleton
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        compatibility,
        (
            i32::from(WORKFLOW_ADMISSION_EPOCH),
            i32::from(JOB_IR_SCHEMA_VERSION),
            i32::from(RUNNER_REQUIREMENTS_SCHEMA_VERSION),
        ),
        "logical activation must use the current admission and payload schemas"
    );
    Ok(())
}

async fn claim_first_logical_job(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult<ClaimedLogicalJobActivation> {
    assert_current_cluster_compatibility(database).await?;

    let preparation = prepare_job(database, fixture, fixture.first_job, 1_000).await?;
    let observed_at = database_now_ms(database).await?;
    let left_request = orchestration_selection_request(71, 81, observed_at, 2_000);
    let right_request = orchestration_selection_request(72, 82, observed_at, 2_000);
    let left_store = database.store().clone();
    let right_store = database.store().clone();
    let (left, right) = tokio::join!(
        left_store.claim_next_logical_job_orchestration(left_request.clone()),
        right_store.claim_next_logical_job_orchestration(right_request.clone()),
    );
    let (selected, winning_request) = match (left?, right?) {
        (
            LogicalJobOrchestrationSelectionOutcome::Selected(selected),
            LogicalJobOrchestrationSelectionOutcome::Idle
            | LogicalJobOrchestrationSelectionOutcome::Contended,
        ) => (selected, left_request),
        (
            LogicalJobOrchestrationSelectionOutcome::Idle
            | LogicalJobOrchestrationSelectionOutcome::Contended,
            LogicalJobOrchestrationSelectionOutcome::Selected(selected),
        ) => (selected, right_request),
        outcome => panic!("exactly one concurrent claim must win: {outcome:?}"),
    };
    let consumed = consume_orchestration(database, selected.clone()).await?;
    let first_claim = match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed.clone(),
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            panic!("expected activation authority, got {authority:?}")
        }
    };
    assert_eq!(
        first_claim.claim().input_digest(),
        preparation.input_digest()
    );
    assert_eq!(first_claim.claim().generation().get(), 1);
    assert_eq!(
        first_claim.execution().workflow_id(),
        fixture.command.workflow_id()
    );
    assert_eq!(first_claim.execution().workflow_name(), "Verify");
    assert_eq!(first_claim.execution().git_ref(), "refs/heads/main");
    assert_eq!(first_claim.execution().run_number(), 1);
    assert_eq!(first_claim.execution().run_attempt(), 1);

    let replayed_selection = match database
        .store()
        .claim_next_logical_job_orchestration(winning_request)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => panic!("expected exact selection replay, got {outcome:?}"),
    };
    assert_eq!(replayed_selection, selected);
    let replay = consume_orchestration(database, replayed_selection).await?;
    let replay = match replay.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed,
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            panic!("expected activation replay, got {authority:?}")
        }
    };
    assert!(replay.is_replay());
    assert_eq!(replay.claim(), first_claim.claim());
    let blocked_observed_at = database_now_ms(database).await?;
    assert!(matches!(
        database
            .store()
            .claim_next_logical_job_orchestration(orchestration_selection_request(
                73,
                83,
                blocked_observed_at,
                60_000,
            ))
            .await?,
        LogicalJobOrchestrationSelectionOutcome::Idle
    ));
    let dependent_state: String =
        sqlx::query_scalar("SELECT state FROM logical_workflow_jobs WHERE id = $1")
            .bind(fixture.second_job.as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(dependent_state, "pending");
    Ok(first_claim)
}

async fn take_over_and_publish_logical_job(
    database: &TestDatabase,
    fixture: &Fixture,
    first_claim: &ClaimedLogicalJobActivation,
) -> TestResult {
    let first_instance = instance(first_claim, 0, 1, 1_000, 90);
    let stale_publication = PublishLogicalJobActivation::new(
        first_claim.claim().clone(),
        true,
        vec![first_instance.clone()],
        first_claim.claim().claimed_at(),
    )
    .expect("stale request is structurally valid");
    wait_until_database_after(database, first_claim.claim().expires_at().get()).await?;
    let takeover = select_orchestration(database, 74, 84, 60_000).await?;
    assert_eq!(
        takeover.selected().target().logical_job_id(),
        fixture.first_job
    );
    let takeover = match takeover.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed.clone(),
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            return Err(format!("expected takeover activation, got {authority:?}").into());
        }
    };
    assert_eq!(takeover.claim().generation().get(), 2);
    let takeover_instance = instance(&takeover, 0, 1, 1_000, 90);
    assert_eq!(first_instance.id(), takeover_instance.id());
    assert!(matches!(
        database
            .store()
            .publish_logical_job_activation(stale_publication)
            .await,
        Err(LogicalActivationStoreError::ClaimRejected)
    ));

    let receipt = database
        .store()
        .publish_logical_job_activation(
            PublishLogicalJobActivation::new(
                takeover.claim().clone(),
                true,
                vec![takeover_instance],
                UnixMillis::new(database_now_ms(database).await?),
            )
            .expect("takeover publication"),
        )
        .await?;
    assert!(!receipt.is_replay());
    assert_eq!(receipt.claim().generation().get(), 2);
    Ok(())
}

async fn assert_published_instances(
    database: &TestDatabase,
    fixture: &Fixture,
    output_digest: Sha256Digest,
) -> TestResult {
    let publication_shape: (Vec<u8>, i32, i16, i16) = sqlx::query_as(
        r"
        SELECT activation_output_digest, instance_count,
               job_ir_version, runtime_context_schema
        FROM logical_workflow_activation_publications
        WHERE logical_job_id = $1
        ",
    )
    .bind(fixture.first_job.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(publication_shape.0, output_digest.as_bytes());
    assert_eq!(
        (
            publication_shape.1,
            publication_shape.2,
            publication_shape.3
        ),
        (
            2,
            i16::try_from(JOB_IR_SCHEMA_VERSION)?,
            i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION)?,
        )
    );

    let instance_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM logical_workflow_instances WHERE logical_job_id = $1",
    )
    .bind(fixture.first_job.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(instance_count, 2);
    assert!(
        sqlx::query(
            "UPDATE logical_workflow_instances SET matrix_digest = $2 WHERE logical_job_id = $1",
        )
        .bind(fixture.first_job.as_uuid())
        .bind([9_u8; 32].as_slice())
        .execute(database.pool())
        .await
        .is_err(),
        "published instance descriptors are immutable"
    );

    let run_id = fixture.command.run_id().as_uuid();
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE run_id = $1")
        .bind(run_id)
        .fetch_one(database.pool())
        .await?;
    let attempts: i64 = sqlx::query_scalar(
        r"
        SELECT count(*) FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        WHERE job.run_id = $1
        ",
    )
    .bind(run_id)
    .fetch_one(database.pool())
    .await?;
    let dependencies: i64 =
        sqlx::query_scalar("SELECT count(*) FROM job_dependencies WHERE run_id = $1")
            .bind(run_id)
            .fetch_one(database.pool())
            .await?;
    assert_eq!(
        (jobs, attempts, dependencies),
        (0, 0, 0),
        "descriptor publication must not create runnable work"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_claim_takeover_and_stale_generation_are_fenced() -> TestResult {
    run_with_database(|database| async move {
        let mut fixture = fixture(&database, "activation-claim", 1_000).await?;
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &mut fixture).await?;
        let first_claim = claim_first_logical_job(&database, &fixture).await?;
        take_over_and_publish_logical_job(&database, &fixture, &first_claim).await?;
        Ok(())
    })
    .await
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(actual, Some(expected), "unexpected database error: {error}");
}

async fn assert_environment_evidence_contract(
    database: &TestDatabase,
    publication: &PublishLogicalJobActivation,
) -> TestResult {
    let stored: Vec<(Uuid, Option<String>, String, String, String)> = sqlx::query_as(
        r"
        SELECT instance_id, environment_normalized_name, event_trust, source_kind,
               reusable_secret_permission
        FROM logical_workflow_job_environment_evidence
        ORDER BY instance_id
        ",
    )
    .fetch_all(database.pool())
    .await?;
    let mut expected = publication
        .instances()
        .iter()
        .map(|instance| {
            (
                instance.id().as_uuid(),
                None,
                "trusted".to_owned(),
                "same_repository".to_owned(),
                "none".to_owned(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort_unstable_by_key(|row| row.0);
    assert_eq!(stored, expected);
    let columns: Vec<String> = sqlx::query_scalar(
        r"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'logical_workflow_job_environment_evidence'
        ORDER BY ordinal_position
        ",
    )
    .fetch_all(database.pool())
    .await?;
    assert_eq!(
        columns,
        [
            "instance_id",
            "environment_normalized_name",
            "event_trust",
            "source_kind",
            "reusable_secret_permission",
            "created_at_ms",
        ]
    );
    for (event_trust, source_kind, reusable_permission, expected_constraint) in [
        (
            "trusted",
            "fork",
            "none",
            "job_environment_evidence_source_trust",
        ),
        (
            "trusted",
            "same_repository",
            "explicit",
            "job_environment_evidence_exact",
        ),
    ] {
        let error = sqlx::query(
            r"
            INSERT INTO logical_workflow_job_environment_evidence (
                instance_id, environment_normalized_name, event_trust,
                source_kind, reusable_secret_permission, created_at_ms
            ) VALUES ($1, NULL, $2, $3, $4, $5)
            ",
        )
        .bind(publication.instances()[0].id().as_uuid())
        .bind(event_trust)
        .bind(source_kind)
        .bind(reusable_permission)
        .bind(publication.published_at().get())
        .execute(database.pool())
        .await
        .expect_err("invalid activation evidence must fail closed");
        assert_constraint(&error, expected_constraint);
    }
    for mutation in [
        "UPDATE logical_workflow_job_environment_evidence SET event_trust = event_trust",
        "DELETE FROM logical_workflow_job_environment_evidence",
        "TRUNCATE logical_workflow_job_environment_evidence",
    ] {
        let error = sqlx::query(mutation)
            .execute(database.pool())
            .await
            .expect_err("environment evidence is append-only");
        assert_constraint(&error, "job_environment_evidence_append_only");
    }
    Ok(())
}

fn publication_with_changed_environment_evidence(
    publication: &PublishLogicalJobActivation,
) -> PublishLogicalJobActivation {
    let mut instances = publication.instances().to_vec();
    let original_evidence = instances[0]
        .environment_gate()
        .expect("original environment evidence")
        .clone();
    instances[0] =
        instances[0]
            .clone()
            .with_environment_gate(JobEnvironmentActivationEvidence::new(
                original_evidence.environment().cloned(),
                JobEventTrust::Untrusted,
                original_evidence.source_kind(),
                original_evidence.reusable_secret_permission(),
            ));
    PublishLogicalJobActivation::new_with_scheduling_policy(
        publication.claim().clone(),
        publication.condition_matched(),
        instances,
        publication.scheduling_policy().clone(),
        publication.published_at(),
    )
    .expect("evidence-only publication change")
}

fn publication_with_changed_job_ir_reference(
    claimed: &ClaimedLogicalJobActivation,
    publication: &PublishLogicalJobActivation,
) -> PublishLogicalJobActivation {
    let original = &publication.instances()[0];
    let identity = JobInstanceIdentity::new(
        claimed.logical_key().as_str(),
        original.matrix_index(),
        original.matrix_total(),
        original.matrix_digest(),
    )
    .expect("original matrix identity");
    let changed_job_ir = LogicalActivationObject::job_ir(
        Sha256Digest::from_bytes([0xee; 32]),
        original.job_ir().object_key().clone(),
        original.job_ir().encoded_size(),
    )
    .expect("changed JobIR reference");
    let changed_descriptor = ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        original.workspace(),
        changed_job_ir,
        original.runtime_context().clone(),
        original
            .environment_gate()
            .expect("original environment evidence")
            .clone(),
    )
    .expect("content-reference-only publication change");
    let mut instances = publication.instances().to_vec();
    instances[0] = changed_descriptor;
    PublishLogicalJobActivation::new_with_scheduling_policy(
        publication.claim().clone(),
        publication.condition_matched(),
        instances,
        publication.scheduling_policy().clone(),
        publication.published_at(),
    )
    .expect("changed content reference publication")
}

async fn assert_scheduling_policy_roundtrip_and_conflict(
    database: &TestDatabase,
    claimed: &ClaimedLogicalJobActivation,
    publication: &PublishLogicalJobActivation,
    scheduling_policy: &ResolvedLogicalJobSchedulingPolicy,
) -> TestResult<LogicalJobSchedulingPolicyScope> {
    let scheduling_scope = LogicalJobSchedulingPolicyScope::for_claim(claimed.claim());
    assert_eq!(
        database
            .store()
            .resolved_logical_job_scheduling_policy(&scheduling_scope)
            .await?,
        Some(scheduling_policy.clone())
    );

    let changed_policy = ResolvedLogicalJobSchedulingPolicy::for_claim(
        claimed.claim(),
        Some(2),
        publication.instances().len(),
    )
    .expect("changed scheduling policy");
    let changed_policy_publication = PublishLogicalJobActivation::new_with_scheduling_policy(
        claimed.claim().clone(),
        true,
        publication.instances().to_vec(),
        changed_policy,
        publication.published_at(),
    )
    .expect("changed-policy publication");
    assert_ne!(
        changed_policy_publication.output_digest(),
        publication.output_digest(),
        "the resolved scheduling policy must authenticate the publication root"
    );
    assert!(matches!(
        database
            .store()
            .publish_logical_job_activation(changed_policy_publication)
            .await,
        Err(LogicalActivationStoreError::PublicationConflict)
    ));
    Ok(scheduling_scope)
}

async fn corrupt_scheduling_policy_and_assert_read_fails(
    database: &TestDatabase,
    logical_job_id: LogicalWorkflowJobId,
    scheduling_scope: &LogicalJobSchedulingPolicyScope,
) -> TestResult {
    sqlx::query(
        "ALTER TABLE logical_workflow_activation_publications DISABLE TRIGGER \
         logical_workflow_activation_publications_reject_update",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        "ALTER TABLE logical_workflow_activation_publications DROP CONSTRAINT \
         logical_workflow_activation_publications_parallel_resolution_exact",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        "UPDATE logical_workflow_activation_publications \
         SET effective_max_parallel = 2 WHERE logical_job_id = $1",
    )
    .bind(logical_job_id.as_uuid())
    .execute(database.pool())
    .await?;
    assert!(matches!(
        database
            .store()
            .resolved_logical_job_scheduling_policy(scheduling_scope)
            .await,
        Err(LogicalActivationStoreError::Store(_))
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_renewal_replays_and_only_latest_generation_can_publish() -> TestResult {
    run_with_database(|database| async move {
        let mut fixture = fixture(&database, "activation-renew", 5_000).await?;
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &mut fixture).await?;
        let preparation = prepare_job(&database, &fixture, fixture.first_job, 5_000).await?;
        let selected = select_orchestration(&database, 5_301, 301, 2_000).await?;
        let claimed = match selected.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed.clone(),
            authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                return Err(format!("expected activation, got {authority:?}").into());
            }
        };
        assert_eq!(claimed.claim().input_digest(), preparation.input_digest());
        let descriptor = instance(&claimed, 0, 1, 5_000, 140);
        let first_renewal =
            RenewLogicalJobActivation::new(claimed.claim().clone(), 2_000).expect("renewal");
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.renew_logical_job_activation(first_renewal.clone()),
            right_store.renew_logical_job_activation(first_renewal.clone()),
        );
        let left = left?;
        let right = right?;
        assert_eq!(left, right);
        assert_eq!(left.predecessor(), claimed.claim());
        assert_eq!(left.successor_generation().get(), 2);
        let current = consume_orchestration(&database, selected.selected().clone()).await?;
        let current = match current.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed.clone(),
            authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                return Err(format!("expected renewed activation, got {authority:?}").into());
            }
        };
        assert_eq!(current.claim().generation(), left.successor_generation());
        assert_eq!(current.claim().claimed_at(), left.successor_claimed_at());
        assert_eq!(current.claim().expires_at(), left.successor_expires_at());

        let stale_publication = PublishLogicalJobActivation::new(
            claimed.claim().clone(),
            true,
            vec![descriptor.clone()],
            UnixMillis::new(database_now_ms(&database).await?),
        )
        .expect("old-fence publication is structurally valid");
        assert!(matches!(
            database
                .store()
                .publish_logical_job_activation(stale_publication)
                .await,
            Err(LogicalActivationStoreError::ClaimRejected)
        ));

        let second_renewal =
            RenewLogicalJobActivation::new(current.claim().clone(), 2_000).expect("second renewal");
        let latest = database
            .store()
            .renew_logical_job_activation(second_renewal)
            .await?;
        assert_eq!(latest.successor_generation().get(), 3);
        let predecessor_replay = database
            .store()
            .renew_logical_job_activation(first_renewal)
            .await?;
        assert_eq!(predecessor_replay, left);
        let current = consume_orchestration(&database, selected.selected().clone()).await?;
        let current = match current.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed,
            authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                return Err(format!("expected latest activation, got {authority:?}").into());
            }
        };
        assert_eq!(current.claim().generation(), latest.successor_generation());
        assert_eq!(current.claim().claimed_at(), latest.successor_claimed_at());
        assert_eq!(current.claim().expires_at(), latest.successor_expires_at());

        let publication = PublishLogicalJobActivation::new(
            current.claim().clone(),
            true,
            vec![descriptor],
            UnixMillis::new(database_now_ms(&database).await?),
        )
        .expect("latest-fence publication");
        let receipt = database
            .store()
            .publish_logical_job_activation(publication)
            .await?;
        assert_eq!(receipt.claim().generation().get(), 3);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_publication_replays_exact_descriptors_and_nothing_runnable() -> TestResult {
    run_with_database(|database| async move {
        let mut fixture = fixture(&database, "activation-publish", 2_000).await?;
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &mut fixture).await?;
        let preparation = prepare_job(&database, &fixture, fixture.first_job, 2_000).await?;
        let selected = select_orchestration(&database, 2_091, 91, 60_000).await?;
        let claimed = match selected.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed.clone(),
            authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                return Err(format!("expected activation, got {authority:?}").into());
            }
        };
        assert_eq!(claimed.claim().input_digest(), preparation.input_digest());
        let gate_evidence = JobEnvironmentActivationEvidence::new(
            None,
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        );
        let instances = vec![
            instance(&claimed, 0, 2, 2_000, 100).with_environment_gate(gate_evidence.clone()),
            instance(&claimed, 1, 2, 2_000, 110).with_environment_gate(gate_evidence),
        ];
        let scheduling_policy = ResolvedLogicalJobSchedulingPolicy::for_claim(
            claimed.claim(),
            Some(1),
            instances.len(),
        )
        .expect("resolved scheduling policy");
        let publication = PublishLogicalJobActivation::new_with_scheduling_policy(
            claimed.claim().clone(),
            true,
            instances,
            scheduling_policy.clone(),
            UnixMillis::new(database_now_ms(&database).await?),
        )
        .expect("publication");
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.publish_logical_job_activation(publication.clone()),
            right_store.publish_logical_job_activation(publication.clone()),
        );
        let left = left?;
        let right = right?;
        assert_ne!(left.is_replay(), right.is_replay());
        assert_eq!(left.output_digest(), right.output_digest());
        assert_eq!(left.instance_count(), 2);
        assert_eq!(left.scheduling_policy(), &scheduling_policy);
        assert_eq!(right.scheduling_policy(), &scheduling_policy);

        let scheduling_scope = assert_scheduling_policy_roundtrip_and_conflict(
            &database,
            &claimed,
            &publication,
            &scheduling_policy,
        )
        .await?;

        assert_environment_evidence_contract(&database, &publication).await?;

        let changed_evidence = publication_with_changed_environment_evidence(&publication);
        assert!(matches!(
            database
                .store()
                .publish_logical_job_activation(changed_evidence)
                .await,
            Err(LogicalActivationStoreError::PublicationConflict)
        ));

        let changed = publication_with_changed_job_ir_reference(&claimed, &publication);
        assert!(matches!(
            database
                .store()
                .publish_logical_job_activation(changed)
                .await,
            Err(LogicalActivationStoreError::PublicationConflict)
        ));
        assert_published_instances(&database, &fixture, left.output_digest()).await?;

        corrupt_scheduling_policy_and_assert_read_fails(
            &database,
            fixture.first_job,
            &scheduling_scope,
        )
        .await?;
        Ok(())
    })
    .await
}

async fn install_matrix_publication_fault(database: &TestDatabase) -> TestResult {
    sqlx::query(
        r"
        CREATE FUNCTION reject_matrix_boundary_insert() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.matrix_index = 128 THEN
                RAISE EXCEPTION 'injected matrix publication failure';
            END IF;
            RETURN NEW;
        END
        $$
        ",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        CREATE TRIGGER reject_matrix_boundary_insert
        BEFORE INSERT ON logical_workflow_instances
        FOR EACH ROW EXECUTE FUNCTION reject_matrix_boundary_insert()
        ",
    )
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn remove_matrix_publication_fault(database: &TestDatabase) -> TestResult {
    sqlx::query("DROP TRIGGER reject_matrix_boundary_insert ON logical_workflow_instances")
        .execute(database.pool())
        .await?;
    sqlx::query("DROP FUNCTION reject_matrix_boundary_insert()")
        .execute(database.pool())
        .await?;
    Ok(())
}

async fn assert_matrix_publication_rolled_back(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult {
    let publication_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM logical_workflow_activation_publications WHERE logical_job_id = $1",
    )
    .bind(fixture.first_job.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let instance_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM logical_workflow_instances WHERE logical_job_id = $1",
    )
    .bind(fixture.first_job.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let state: String = sqlx::query_scalar("SELECT state FROM logical_workflow_jobs WHERE id = $1")
        .bind(fixture.first_job.as_uuid())
        .fetch_one(database.pool())
        .await?;
    assert_eq!(
        (publication_count, instance_count, state.as_str()),
        (0, 0, "activating")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn maximum_matrix_publication_rolls_back_atomically_and_replays_exactly() -> TestResult {
    run_with_database(|database| async move {
        let mut fixture = fixture(&database, "activation-matrix-boundary", 3_000).await?;
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &mut fixture).await?;
        let preparation = prepare_job(&database, &fixture, fixture.first_job, 3_000).await?;
        let selected = select_orchestration(&database, 3_091, 191, 60_000).await?;
        let claimed = match selected.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed.clone(),
            authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                return Err(format!("expected activation, got {authority:?}").into());
            }
        };
        assert_eq!(claimed.claim().input_digest(), preparation.input_digest());

        let total = u32::try_from(automata_ci_store::MAX_LOGICAL_ACTIVATED_INSTANCES)?;
        let instances = (0..total)
            .map(|index| {
                instance(
                    &claimed,
                    index,
                    total,
                    3_000,
                    u8::try_from(index).expect("the 256-instance boundary fits one byte"),
                )
            })
            .collect();
        let publication = PublishLogicalJobActivation::new(
            claimed.claim().clone(),
            true,
            instances,
            UnixMillis::new(database_now_ms(&database).await?),
        )
        .expect("maximum-size publication");
        assert_eq!(publication.instances().len(), 256);

        install_matrix_publication_fault(&database).await?;
        assert!(
            database
                .store()
                .publish_logical_job_activation(publication.clone())
                .await
                .is_err(),
            "the injected 129th descriptor must abort publication"
        );
        assert_matrix_publication_rolled_back(&database, &fixture).await?;
        remove_matrix_publication_fault(&database).await?;

        let first = database
            .store()
            .publish_logical_job_activation(publication.clone())
            .await?;
        assert!(!first.is_replay());
        assert_eq!(first.instance_count(), 256);
        let replay = database
            .store()
            .publish_logical_job_activation(publication)
            .await?;
        assert!(replay.is_replay());
        assert_eq!(first.output_digest(), replay.output_digest());

        let instance_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM logical_workflow_instances WHERE logical_job_id = $1",
        )
        .bind(fixture.first_job.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(instance_count, 256);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn zero_instance_publications_preserve_condition_distinction() -> TestResult {
    run_with_database(|database| async move {
        for (offset, condition_matched, expected_state) in
            [(0_u128, false, "skipped"), (100_u128, true, "activated")]
        {
            let tenant = format!("activation-zero-{offset}");
            let mut fixture = fixture(&database, &tenant, 3_000 + offset).await?;
            seed_tenant(&database, &tenant).await?;
            admit_authenticated_fixture(&database, &mut fixture).await?;
            let preparation =
                prepare_job(&database, &fixture, fixture.first_job, 3_000 + offset).await?;
            let selected =
                select_orchestration(&database, 3_190 + offset, 200 + offset, 60_000).await?;
            let claimed = match selected.authority() {
                ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed.clone(),
                authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                    return Err(format!("expected activation, got {authority:?}").into());
                }
            };
            assert_eq!(claimed.claim().input_digest(), preparation.input_digest());
            let publication = PublishLogicalJobActivation::new(
                claimed.claim().clone(),
                condition_matched,
                Vec::new(),
                UnixMillis::new(database_now_ms(&database).await?),
            )
            .expect("zero-instance publication");
            let receipt = database
                .store()
                .publish_logical_job_activation(publication)
                .await?;
            assert_eq!(receipt.instance_count(), 0);
            assert_eq!(receipt.condition_matched(), condition_matched);
            let state: String =
                sqlx::query_scalar("SELECT state FROM logical_workflow_jobs WHERE id = $1")
                    .bind(fixture.first_job.as_uuid())
                    .fetch_one(database.pool())
                    .await?;
            assert_eq!(state, expected_state);
        }
        Ok(())
    })
    .await
}
