#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use automata_ci_core::{
    JobAuthorityProfile, RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AdmissionObject,
    AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation,
    ClaimNextLogicalJobOrchestration, ClaimProviderDelivery,
    ConsumeSelectedLogicalJobOrchestration, ConsumedLogicalJobOrchestrationAuthority,
    EnsureGithubServerServiceAuthority, GithubCheckHeadSha, GithubCheckName,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    LogicalActivationPreparationStore as _, LogicalActivationPreparationTarget,
    LogicalActivationWorkerId, LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionId,
    LogicalWorkSelectionRepository as _, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowAdmissionStoreError, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, TenantScope, WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Logical orchestration test tenant', 1, 1)
        ",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

fn object(key: String, digest: u8) -> AdmissionObject {
    object_with_media(key, digest, "application/json")
}

fn object_with_media(key: String, digest: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("object key"),
        768,
        media_type,
    )
    .expect("admission object")
}

async fn prepare_job(
    database: &TestDatabase,
    command: &AdmitLogicalWorkflowRun,
    logical_job_id: LogicalWorkflowJobId,
    namespace: u128,
) -> TestResult<automata_ci_store::LogicalActivationPreparationReceipt> {
    let target = LogicalActivationPreparationTarget::new(
        command.tenant().clone(),
        command.run_id(),
        command.root_invocation_id(),
        logical_job_id,
    )?;
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(
                0xa300_0000_0000_0000_0000_0000_0000_0000 | namespace,
            ))?,
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(namespace + 900))?,
            UnixMillis::new(observed_at),
            60_000,
        )?)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected preparation selection, got {outcome:?}").into()),
    };
    assert_eq!(selected.target(), &target);
    let consumed = database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?;
    let claimed = match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            return Err(format!("expected preparation authority, got {authority:?}").into());
        }
    };
    let bound_at = database_now_ms(database).await?;
    Ok(database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            claimed.descriptor().clone(),
            claimed.claim().clone(),
            claimed.descriptor().base_context().clone(),
            object_with_media(
                format!("preparation/{namespace}/needs.pb"),
                32,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            UnixMillis::new(bound_at),
        )?)
        .await?)
}

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}

fn fixture_manifest(tenant: TenantScope, namespace: u128) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    GithubProviderManifest::new(
        tenant,
        ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 20))
            .expect("provider connection"),
        ProviderInstallationId::new(u64::try_from(namespace + 101).expect("installation"))
            .expect("installation"),
        ProviderRepositoryId::new(u64::try_from(namespace + 102).expect("repository"))
            .expect("repository"),
        GithubRepositoryName::new(format!("sample-owner/sample-{namespace}"))
            .expect("repository name"),
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(u64::try_from(namespace + 103).expect("app ID"))
            .expect("app ID"),
        GithubServerServiceAppClientId::new(format!("Iv1.logical-orchestration-{namespace}"))
            .expect("app client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x71; 32]),
        GithubServerServiceRevision::new(1).expect("configuration revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([0x72; 32]))
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

async fn stage_authenticated_admission(
    database: &TestDatabase,
    command: &AdmitLogicalWorkflowRun,
    namespace: u128,
) -> TestResult<(AdmitLogicalWorkflowRun, AuthenticatedGithubDeliveryClaim)> {
    let manifest = fixture_manifest(command.tenant().clone(), namespace);
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
                GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(namespace + 21))?,
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
                Sha256Digest::from_bytes([0x73; 32]),
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
                    format!("logical-orchestration-{namespace}"),
                )?,
                command.request_digest(),
                command.event().clone(),
                UnixMillis::new(delivery_observed_at),
            )?,
            ProviderRepositoryOwnerId::new(u64::try_from(namespace + 104)?)?,
            ProviderRepositoryOwnerId::new(u64::try_from(namespace + 104)?)?,
            GithubCheckHeadSha::new([9; 20])?,
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
        )?)
        .await?;
    let claim_observed_at = database_now_ms(database).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(namespace + 22))?,
            UnixMillis::new(claim_observed_at),
            UnixMillis::new(claim_observed_at + 60_000),
        )?)
        .await?
        .ok_or("accepted GitHub delivery was not claimable")?;
    assert_eq!(claimed.claim().delivery_id(), accepted.delivery_id());
    Ok((
        logical_command_at(command, claimed.claimed_at())?,
        AuthenticatedGithubDeliveryClaim::new(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
        )?,
    ))
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
    if let Some(actor) = command.actor() {
        builder = builder.actor(actor);
    }
    if let Some(base_context) = command.base_context() {
        builder = builder.base_context(base_context.clone());
    }
    Ok(builder.build()?)
}

fn fixture(
    tenant: &str,
    idempotency_key: &str,
    request_digest: u8,
    namespace: u128,
) -> AdmitLogicalWorkflowRun {
    fixture_at(
        tenant,
        idempotency_key,
        request_digest,
        namespace,
        UnixMillis::new(1_000),
    )
}

fn fixture_at(
    tenant: &str,
    idempotency_key: &str,
    request_digest: u8,
    namespace: u128,
    admitted_at: UnixMillis,
) -> AdmitLogicalWorkflowRun {
    let tenant_scope = TenantScope::from_authenticated_tenant_id(tenant).expect("tenant");
    let manifest = fixture_manifest(tenant_scope.clone(), namespace);
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let root_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("root");
    let first_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("first job");
    let second_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 7)).expect("second job");
    let first = AdmittedLogicalWorkflowJob::new(
        first_id,
        WorkflowJobKey::new("prepare").expect("key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("first job");
    let second = AdmittedLogicalWorkflowJob::new(
        second_id,
        WorkflowJobKey::new("verify").expect("key"),
        1,
        LogicalWorkflowJobKind::ReusableWorkflow,
        vec![first_id],
    )
    .expect("second job");
    AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(idempotency_key).expect("idempotency"),
        Sha256Digest::from_bytes([request_digest; 32]),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            manifest.github_repository_id().get().to_string(),
            "sample-owner",
            format!("sample-{namespace}"),
        )
        .expect("repository"),
        workflow_id,
        ".github/workflows/ci.yml",
        "Verify",
        "refs/heads/main",
        snapshot_id,
        object(format!("logical/{namespace}/source"), 1),
        object_with_media(
            format!("logical/{namespace}/plan-v2"),
            2,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        root_id,
        "push",
        object(format!("logical/{namespace}/event"), 3),
        vec![9; 20],
        vec![first, second],
        admitted_at,
    )
    .actor("sample-actor")
    .base_context(object_with_media(
        format!("logical/{namespace}/base-context.pb"),
        4,
        "application/vnd.automata.job-runtime-context.protobuf",
    ))
    .build()
    .expect("logical admission fixture")
}

async fn assert_logical_admission_shape(
    database: &TestDatabase,
    snapshot_id: WorkflowSnapshotId,
    run_id: RunId,
    root_id: LogicalWorkflowInvocationId,
    base_context: &AdmissionObject,
) -> TestResult {
    let run_shape: (i32, i32, String) = sqlx::query_as(
        "SELECT admission_epoch, plan_schema, status FROM workflow_runs WHERE id = $1",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(run_shape, (4, 2, "queued".to_owned()));

    let snapshot_epoch: i32 =
        sqlx::query_scalar("SELECT admission_epoch FROM workflow_snapshots WHERE id = $1")
            .bind(snapshot_id.as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(snapshot_epoch, 4);

    let marker: (Uuid, i16, Vec<u8>, String, i64) = sqlx::query_as(
        r"
        SELECT root_invocation_id, orchestration_schema, admission_digest,
               state, revision
        FROM workflow_plan_v2_runs WHERE run_id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(marker.0, root_id.as_uuid());
    assert_eq!((marker.1, marker.2), (1, vec![41; 32]));
    assert_eq!((marker.3.as_str(), marker.4), ("pending", 1));

    let marker_context: (Vec<u8>, String, i64, String, i16) = sqlx::query_as(
        r"
        SELECT base_context_digest, base_context_object_key, base_context_size_bytes,
               base_context_media_type, base_context_schema
        FROM workflow_plan_v2_runs WHERE run_id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        marker_context,
        (
            base_context.digest().as_bytes().to_vec(),
            base_context.object_key().as_str().to_owned(),
            i64::try_from(base_context.encoded_size())?,
            base_context.media_type().to_owned(),
            2,
        )
    );

    let invocation: (i16, String, Vec<u8>) = sqlx::query_as(
        r"
        SELECT plan_schema, state, plan_digest
        FROM workflow_plan_v2_invocations WHERE id = $1 AND run_id = $2
        ",
    )
    .bind(root_id.as_uuid())
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(invocation, (2, "pending".to_owned(), vec![2; 32]));

    let logical_jobs: Vec<(String, i32, String, String)> = sqlx::query_as(
        r"
        SELECT logical_key, source_order, execution_kind, state
        FROM workflow_plan_v2_jobs WHERE run_id = $1 ORDER BY source_order
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_all(database.pool())
    .await?;
    assert_eq!(
        logical_jobs,
        vec![
            (
                "prepare".to_owned(),
                0,
                "steps".to_owned(),
                "pending".to_owned(),
            ),
            (
                "verify".to_owned(),
                1,
                "reusable_workflow".to_owned(),
                "pending".to_owned(),
            ),
        ]
    );
    let dependency_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflow_plan_v2_dependencies WHERE run_id = $1")
            .bind(run_id.as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(dependency_count, 1);
    Ok(())
}

async fn assert_no_concrete_jobs(database: &TestDatabase, run_id: RunId) -> TestResult {
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE run_id = $1")
        .bind(run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
    let attempts: i64 = sqlx::query_scalar(
        r"
        SELECT count(*) FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        WHERE job.run_id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let dependencies: i64 =
        sqlx::query_scalar("SELECT count(*) FROM job_dependencies WHERE run_id = $1")
            .bind(run_id.as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!((jobs, attempts, dependencies), (0, 0, 0));
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn admission_is_atomic_exact_and_has_no_concrete_jobs() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "logical-atomic").await?;
        let command = fixture("logical-atomic", "delivery-atomic", 41, 100);
        let run_id = command.run_id();
        let root_id = command.root_invocation_id();
        let (command, authenticated) =
            stage_authenticated_admission(&database, &command, 100).await?;
        let first = database
            .store()
            .admit_authenticated_github_delivery(
                command.clone(),
                authenticated,
                command.admitted_at(),
            )
            .await?;
        let replay = database
            .store()
            .admit_authenticated_github_delivery(
                command.clone(),
                authenticated,
                command.admitted_at(),
            )
            .await?;
        assert!(!first.is_replay());
        assert!(replay.is_replay());
        assert_eq!(first.run_id(), replay.run_id());
        assert_eq!(first.root_invocation_id(), replay.root_invocation_id());
        assert_eq!(first.run_number(), 1);
        assert_logical_admission_shape(
            &database,
            first.snapshot_id(),
            run_id,
            root_id,
            command
                .base_context()
                .expect("current admission base context"),
        )
        .await?;
        let tamper = sqlx::query(
            "UPDATE workflow_plan_v2_runs SET base_context_digest = $2 WHERE run_id = $1",
        )
        .bind(run_id.as_uuid())
        .bind(vec![0x55_u8; 32])
        .execute(database.pool())
        .await
        .expect_err("admission base context must be immutable");
        assert_eq!(
            tamper
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("workflow_plan_v2_runs_base_context_immutable"),
        );
        assert_no_concrete_jobs(&database, run_id).await?;
        let subject_evidence_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_workflow_run_subject_evidence WHERE run_id = $1",
        )
        .bind(run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(subject_evidence_count, 1);
        let evidence_required: bool = sqlx::query_scalar(
            "SELECT github_subject_evidence_required FROM workflow_admission_receipts WHERE run_id = $1",
        )
        .bind(run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(evidence_required);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_replay_has_one_insert_and_changed_digest_conflicts() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "logical-replay").await?;
        let command = fixture("logical-replay", "delivery-replay", 51, 200);
        let (command, authenticated) =
            stage_authenticated_admission(&database, &command, 200).await?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.admit_authenticated_github_delivery(
                command.clone(),
                authenticated,
                command.admitted_at(),
            ),
            right_store.admit_authenticated_github_delivery(
                command.clone(),
                authenticated,
                command.admitted_at(),
            ),
        );
        let left = left?;
        let right = right?;
        assert_ne!(left.is_replay(), right.is_replay());
        assert_eq!(left.run_id(), right.run_id());
        assert_eq!(left.run_number(), right.run_number());

        let changed = fixture("logical-replay", "delivery-replay", 52, 300);
        let (changed, changed_authenticated) =
            stage_authenticated_admission(&database, &changed, 300).await?;
        assert!(matches!(
            database
                .store()
                .admit_authenticated_github_delivery(
                    changed.clone(),
                    changed_authenticated,
                    changed.admitted_at(),
                )
                .await,
            Err(LogicalWorkflowAdmissionStoreError::IdempotencyConflict)
        ));
        let marker_count: i64 = sqlx::query_scalar("SELECT count(*) FROM workflow_plan_v2_runs")
            .fetch_one(database.pool())
            .await?;
        assert_eq!(marker_count, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn descriptors_are_immutable_and_activation_claim_shape_is_strict() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "logical-constraints").await?;
        let command = fixture("logical-constraints", "delivery-constraints", 61, 400);
        let run_id = command.run_id().as_uuid();
        let first_job_id = command.jobs()[0].id().as_uuid();
        let (command, authenticated) =
            stage_authenticated_admission(&database, &command, 400).await?;
        database
            .store()
            .admit_authenticated_github_delivery(
                command.clone(),
                authenticated,
                command.admitted_at(),
            )
            .await?;

        assert!(
            sqlx::query("UPDATE workflow_runs SET plan_digest = $2 WHERE id = $1",)
                .bind(run_id)
                .bind([8_u8; 32].as_slice())
                .execute(database.pool())
                .await
                .is_err()
        );
        assert!(
            sqlx::query("UPDATE workflow_plan_v2_jobs SET logical_key = 'changed' WHERE id = $1",)
                .bind(first_job_id)
                .execute(database.pool())
                .await
                .is_err()
        );
        assert!(
            sqlx::query(
                r"
                UPDATE workflow_plan_v2_jobs
                SET state = 'activating', activation_fence = 1
                WHERE id = $1
                ",
            )
            .bind(first_job_id)
            .execute(database.pool())
            .await
            .is_err()
        );

        let preparation = prepare_job(&database, &command, command.jobs()[0].id(), 400).await?;
        let expected_target = LogicalActivationPreparationTarget::new(
            command.tenant().clone(),
            command.run_id(),
            command.root_invocation_id(),
            command.jobs()[0].id(),
        )?;
        let observed_at = database_now_ms(&database).await?;
        let selected = match database
            .store()
            .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
                LogicalWorkSelectionId::from_uuid(Uuid::from_u128(
                    0xa300_0000_0000_0000_0000_0000_0000_0401,
                ))?,
                LogicalActivationWorkerId::from_uuid(Uuid::from_u128(999))?,
                UnixMillis::new(observed_at),
                60_000,
            )?)
            .await?
        {
            LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
            outcome => panic!("expected activation selection, got {outcome:?}"),
        };
        assert_eq!(selected.target(), &expected_target);
        let consumed = database
            .store()
            .consume_selected_logical_job_orchestration(
                ConsumeSelectedLogicalJobOrchestration::new(selected),
            )
            .await?;
        match consumed.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
                assert_eq!(claimed.claim().generation().get(), 1);
                assert_eq!(claimed.claim().input_digest(), preparation.input_digest());
            }
            authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
                panic!("expected activation authority, got {authority:?}");
            }
        }
        assert!(
            sqlx::query(
                r"
                UPDATE workflow_plan_v2_jobs
                SET activation_expires_at_ms = activation_claimed_at_ms
                WHERE id = $1
                ",
            )
            .bind(first_job_id)
            .execute(database.pool())
            .await
            .is_err()
        );
        Ok(())
    })
    .await
}
