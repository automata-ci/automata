#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use std::{collections::BTreeMap, time::Duration};

use automata_ci_core::{
    Architecture, AttemptId, CompiledValueTemplate, ContextValue, JobAuthorityProfile,
    JobConclusion, JobContentReference, JobExecutionContext, JobId, JobInstanceIdentity, JobIr,
    JobIrEnvelope, JobIrVersion, JobPermissionRequest, JobResult, JobRuntimeContext,
    JobSecretExposure, JobSource, Located, LogicalJobKind, LogicalJobTemplate,
    LogicalRunStepTemplate, LogicalRunnerTemplate, LogicalStepKind, LogicalStepTemplate,
    OperatingSystem, OperationId, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, RunId,
    RunValueTemplates, RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    StepJobTemplate, StrategyContext, UnixMillis, ValueTemplate, WorkflowEventProvenance,
    WorkflowId, WorkflowJobKey, WorkflowPlan, WorkflowSourceProvenance, WorkflowStepKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmitWorkflowRun,
    AdmittedLogicalWorkflowJob, AdmittedWorkflowJob, AuthenticatedGithubDeliveryClaim,
    BindLogicalActivationPreparation, ClaimLogicalInstanceResult, ClaimLogicalJobResult,
    ClaimLogicalRunFinalization, ClaimNextLogicalInstanceMaterialization,
    ClaimNextLogicalJobOrchestration, ClaimProviderDelivery, ClaimedLogicalInstanceMaterialization,
    ClaimedLogicalJobActivation, CommitLogicalInstanceMaterialization, CommitLogicalInstanceResult,
    CommitLogicalJobResult, CommitLogicalRunFinalization,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, ConsumedSelectedLogicalInstanceMaterialization,
    EnsureGithubServerServiceAuthority, GithubCheckHeadSha, GithubCheckName,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE, LogicalActivationObject,
    LogicalActivationPreparationStore as _, LogicalActivationRepository as _,
    LogicalActivationWorkerId, LogicalInstanceMaterializationSelectionOutcome,
    LogicalInstanceMaterializationTarget, LogicalInstanceResultClaimOutcome,
    LogicalInstanceResultRepository as _, LogicalInstanceResultTarget,
    LogicalInstanceResultWorkerId, LogicalJobOrchestrationSelectionOutcome,
    LogicalJobResultClaimOutcome, LogicalJobResultRepository as _, LogicalJobResultTarget,
    LogicalJobResultWorkerId, LogicalMaterializationRepository as _,
    LogicalMaterializationStoreError, LogicalMaterializationWorkerId,
    LogicalRunFinalizationRepository as _, LogicalRunFinalizationWorkerId, LogicalWorkSelectionId,
    LogicalWorkSelectionRepository as _, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInstanceId, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, OpenRunnerSession, ProviderConnectionId,
    ProviderDeliveryClaimOwnerId, ProviderDeliveryIdentity, ProviderDeliveryRepository as _,
    ProviderInstallationId, ProviderRepositoryCoordinates, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, PublishLogicalJobActivation,
    RoutingDocument, RunReconciliationRepository as _, RunnableAttemptRepository as _,
    RunnableScanLimit, RunnableScanRequest, RunnerGeneration, RunnerProtocolVersion,
    RunnerSessionFence, RunnerSessionRepository as _, StableRunnerSlot, StoreError, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowAdmissionRepository as _, WorkflowConcurrency,
    WorkflowPlanRepository as _, WorkflowRunStatus, WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

struct Fixture {
    tenant: String,
    namespace: u128,
    manifest: GithubProviderManifest,
    clock_origin_ms: i64,
    command: AdmitLogicalWorkflowRun,
    logical_job_id: LogicalWorkflowJobId,
    plan: WorkflowPlan,
    plan_bytes: Vec<u8>,
}

impl Fixture {
    fn at(&self, legacy_ms: i64) -> UnixMillis {
        UnixMillis::new(self.clock_origin_ms + (legacy_ms - 1_000) * 10)
    }
}

struct PreparedInstance {
    activated: ActivatedLogicalInstanceDescriptor,
    envelope: JobIrEnvelope,
    encoded: Vec<u8>,
    runtime_context: JobRuntimeContext,
    runtime_encoded: Vec<u8>,
}

struct MaterializationRaceFixture {
    fixture: Fixture,
    prepared: PreparedInstance,
    claimed: ClaimedLogicalInstanceMaterialization,
}

struct ReplacementAdmission {
    command: AdmitWorkflowRun,
    run_id: RunId,
}

const MATERIALIZATION_RACE_GROUP: &str = "logical-materialization-race";

#[derive(Debug, Eq, PartialEq)]
struct DurableAttemptSafety {
    secret_exposure: String,
    raw_log_disposition: String,
    requested_visibility: String,
    effective_visibility: String,
    reason: String,
    schema: i32,
    classified_at: i64,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One scenario proves the full fenced crash/replay lifecycle.
async fn exact_replay_takeover_and_duplicate_rows_publish_current_runnable_jobs() -> TestResult {
    run_with_database(|database| async move {
        let mut fixture = fixture(&database, "materialization-main", 10_000).await?;
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &mut fixture, true).await?;
        let activated_claim = claim_activation(&database, &fixture, 10_100).await?;
        let prepared = [
            prepared_instance(
                &fixture,
                &activated_claim,
                0,
                2,
                [0x77; 32],
                JobAuthorityProfile::Standard,
            ),
            prepared_instance(
                &fixture,
                &activated_claim,
                1,
                2,
                [0x77; 32],
                JobAuthorityProfile::Standard,
            ),
        ];
        database
            .store()
            .publish_logical_job_activation(
                PublishLogicalJobActivation::new(
                    activated_claim.claim().clone(),
                    true,
                    prepared
                        .iter()
                        .map(|instance| instance.activated.clone())
                        .collect(),
                    UnixMillis::new(database_now_ms(&database).await?),
                )?,
            )
            .await?;

        let first_target = target(&fixture, prepared[0].activated.id());
        let first_observed_at = database_now_ms(&database).await?;
        let first_selection_request =
            materialization_selection_request(10_190, 10_200, first_observed_at, 2_000);
        let first_selected = expect_selected_materialization(
            database
                .store()
                .claim_next_logical_instance_materialization(first_selection_request.clone())
                .await?,
        );
        assert_eq!(first_selected.target(), &first_target);
        let first_consumed = consume_materialization(&database, first_selected.clone()).await?;
        let first_claimed = first_consumed.authority().clone();
        assert_eq!(first_claimed.claim().generation().get(), 1);
        let replayed = expect_selected_materialization(
            database
                .store()
                .claim_next_logical_instance_materialization(first_selection_request)
                .await?,
        );
        assert_eq!(replayed, first_selected);
        let replayed_consumed = consume_materialization(&database, replayed).await?;
        assert!(replayed_consumed.authority().is_replay());
        assert_eq!(replayed_consumed.authority().claim(), first_claimed.claim());
        let second_target = target(&fixture, prepared[1].activated.id());
        let second_selected = expect_selected_materialization(
            database
                .store()
                .claim_next_logical_instance_materialization(materialization_selection_request(
                    10_191,
                    10_201,
                    first_observed_at,
                    60_000,
                ))
                .await?,
        );
        assert_eq!(second_selected.target(), &second_target);
        let second = consume_materialization(&database, second_selected).await?;

        let stale_commit = CommitLogicalInstanceMaterialization::new(
            &first_claimed,
            &prepared[0].encoded,
            &prepared[0].envelope,
            &prepared[0].runtime_encoded,
            &prepared[0].runtime_context,
            UnixMillis::new(database_now_ms(&database).await?),
        )?;
        wait_until_database_after(&database, first_claimed.claim().expires_at().get()).await?;
        let takeover_observed_at = database_now_ms(&database).await?;
        let takeover_selected = expect_selected_materialization(
            database
                .store()
                .claim_next_logical_instance_materialization(materialization_selection_request(
                    10_192,
                    10_202,
                    takeover_observed_at,
                    60_000,
                ))
                .await?,
        );
        assert_eq!(takeover_selected.target(), &first_target);
        let takeover = consume_materialization(&database, takeover_selected).await?;
        let takeover = takeover.authority().clone();
        assert_eq!(takeover.claim().generation().get(), 2);
        assert!(matches!(
            database
                .store()
                .commit_logical_instance_materialization(stale_commit)
                .await,
            Err(LogicalMaterializationStoreError::ClaimRejected)
        ));

        let current_commit = CommitLogicalInstanceMaterialization::new(
            &takeover,
            &prepared[0].encoded,
            &prepared[0].envelope,
            &prepared[0].runtime_encoded,
            &prepared[0].runtime_context,
            UnixMillis::new(database_now_ms(&database).await?),
        )?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.commit_logical_instance_materialization(current_commit.clone()),
            right_store.commit_logical_instance_materialization(current_commit),
        );
        let left = left?;
        let right = right?;
        assert_ne!(left.is_replay(), right.is_replay());
        assert_eq!(left.job_id(), right.job_id());
        assert_eq!(left.attempt_id(), right.attempt_id());
        assert_eq!(left.commit_digest(), right.commit_digest());
        let commit_replay = database
            .store()
            .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
                &takeover,
                &prepared[0].encoded,
                &prepared[0].envelope,
                &prepared[0].runtime_encoded,
                &prepared[0].runtime_context,
                left.committed_at(),
            )?)
            .await?;
        assert!(commit_replay.is_replay());
        assert_eq!(commit_replay.job_id(), left.job_id());

        let second_claimed = second.authority().clone();
        let second_receipt = database
            .store()
            .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
                &second_claimed,
                &prepared[1].encoded,
                &prepared[1].envelope,
                &prepared[1].runtime_encoded,
                &prepared[1].runtime_context,
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        assert_ne!(left.job_id(), second_receipt.job_id());
        assert_ne!(left.attempt_id(), second_receipt.attempt_id());
        assert_eq!(
            load_attempt_safety(&database, left.attempt_id()).await?,
            standard_public_attempt_safety(left.committed_at().get())
        );
        assert_eq!(
            load_attempt_safety(&database, second_receipt.attempt_id()).await?,
            standard_public_attempt_safety(second_receipt.committed_at().get())
        );

        let metadata = database.store().get_job_ir_metadata(left.job_id()).await?;
        assert_eq!(metadata.version().get(), 5);
        assert_eq!(metadata.run_id(), fixture.command.run_id());
        assert_eq!(metadata.digest(), prepared[0].activated.job_ir().digest());
        let routing_shape: Vec<(i32, i32, i32)> = sqlx::query_as(
            r"
            SELECT job.admission_epoch, job.job_ir_schema,
                   (job.requirements ->> 'schema_version')::INTEGER
            FROM jobs AS job WHERE job.run_id = $1 ORDER BY job.job_key
            ",
        )
        .bind(fixture.command.run_id().as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(routing_shape, vec![(4, 5, 2), (4, 5, 2)]);
        let runner = open_v5_runner(&database, &fixture.tenant, 10_300).await?;
        let runnable = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                runner,
                StableRunnerSlot::new(1)?,
                RunnableScanLimit::new(10)?,
                UnixMillis::new(database_now_ms(&database).await?),
            ))
            .await?;
        let routed_jobs: Vec<_> = runnable
            .candidates()
            .iter()
            .map(|candidate| {
                assert_eq!(candidate.job_ir().version(), JobIrVersion::current());
                candidate.job_id()
            })
            .collect();
        assert_eq!(routed_jobs, vec![left.job_id(), second_receipt.job_id()]);
        let dependency_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM job_dependencies WHERE run_id = $1")
                .bind(fixture.command.run_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(dependency_count, 0);

        sqlx::query(
            "UPDATE job_attempts SET lifecycle = 'succeeded', changed_at_ms = $3 WHERE job_id IN ($1, $2)",
        )
        .bind(left.job_id().as_uuid())
        .bind(second_receipt.job_id().as_uuid())
        .bind(database_now_ms(&database).await?)
        .execute(database.pool())
        .await?;
        let reconciliation = database
            .store()
            .reconcile_run(
                fixture.command.run_id(),
                UnixMillis::new(database_now_ms(&database).await?),
            )
            .await?;
        assert_eq!(reconciliation.status(), WorkflowRunStatus::InProgress);
        let invalid_completion_at = database_now_ms(&database).await?;
        assert!(
            sqlx::query("UPDATE workflow_runs SET status = 'completed', updated_at_ms = $2 WHERE id = $1")
                .bind(fixture.command.run_id().as_uuid())
                .bind(invalid_completion_at)
                .execute(database.pool())
                .await
                .is_err(),
            "logical runs must not complete before orchestration finalization"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn selector_quarantines_expired_max_materialization_generation_and_advances() -> TestResult {
    run_with_database(|database| async move {
        let mut poisoned_fixture =
            fixture(&database, "materialization-generation-poison", 55_000).await?;
        let poisoned_prepared = publish_single_materialization_candidate(
            &database,
            &mut poisoned_fixture,
            55_100,
            [0x79; 32],
        )
        .await?;
        let poisoned_target = target(&poisoned_fixture, poisoned_prepared.activated.id());
        let observed_at = database_now_ms(&database).await?;
        let selected = expect_selected_materialization(
            database
                .store()
                .claim_next_logical_instance_materialization(materialization_selection_request(
                    55_190,
                    55_200,
                    observed_at,
                    2_000,
                ))
                .await?,
        );
        assert_eq!(selected.target(), &poisoned_target);
        let poisoned = consume_materialization(&database, selected).await?;
        assert_eq!(poisoned.authority().claim().generation().get(), 1);
        wait_until_database_after(&database, poisoned.authority().claim().expires_at().get())
            .await?;

        let expired_at = database_now_ms(&database).await? - 1;
        let mut corruption = database.pool().begin().await?;
        sqlx::query("ALTER TABLE workflow_plan_v2_materialization_claims DISABLE TRIGGER USER")
            .execute(&mut *corruption)
            .await?;
        let updated = sqlx::query(
            r"
            UPDATE workflow_plan_v2_materialization_claims
            SET generation = $2, expires_at_ms = $3
            WHERE instance_id = $1 AND state = 'materializing'
            ",
        )
        .bind(poisoned_target.instance_id().as_uuid())
        .bind(i64::MAX)
        .bind(expired_at)
        .execute(&mut *corruption)
        .await?;
        assert_eq!(updated.rows_affected(), 1);
        sqlx::query("ALTER TABLE workflow_plan_v2_materialization_claims ENABLE TRIGGER USER")
            .execute(&mut *corruption)
            .await?;
        corruption.commit().await?;

        let poison_request = materialization_selection_request(
            55_191,
            55_201,
            database_now_ms(&database).await?,
            60_000,
        );
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(poison_request.clone())
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Quarantined
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(poison_request)
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Quarantined
        ));
        let quarantine: (i64, String) = sqlx::query_as(
            r"
            SELECT authority_generation, failure_kind
            FROM workflow_plan_v2_materialization_work_quarantines
            WHERE instance_id = $1
            ",
        )
        .bind(poisoned_target.instance_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(quarantine, (i64::MAX, "generation_exhausted".to_owned()));

        let mut newer_fixture =
            fixture(&database, "materialization-after-generation-poison", 56_000).await?;
        let newer_prepared = publish_single_materialization_candidate(
            &database,
            &mut newer_fixture,
            56_100,
            [0x7a; 32],
        )
        .await?;
        let newer = select_materialization(&database, 56_190, 56_200).await?;
        assert_eq!(
            newer.authority().claim().target(),
            &target(&newer_fixture, newer_prepared.activated.id())
        );
        assert_eq!(newer.authority().claim().generation().get(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn exact_receipt_replays_after_job_and_run_finalization() -> TestResult {
    run_with_database(|database| async move {
        let mut fixture = fixture(&database, "materialization-terminal-replay", 50_000).await?;
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &mut fixture, true).await?;
        let activation = claim_activation(&database, &fixture, 50_100).await?;
        let prepared = prepared_instance(
            &fixture,
            &activation,
            0,
            1,
            [0x78; 32],
            JobAuthorityProfile::Standard,
        );
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                activation.claim().clone(),
                true,
                vec![prepared.activated.clone()],
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;

        let target = target(&fixture, prepared.activated.id());
        let consumed = select_materialization(&database, 50_190, 50_200).await?;
        assert_eq!(consumed.selected().target(), &target);
        let claimed = consumed.authority().clone();
        let exact_commit = CommitLogicalInstanceMaterialization::new(
            &claimed,
            &prepared.encoded,
            &prepared.envelope,
            &prepared.runtime_encoded,
            &prepared.runtime_context,
            UnixMillis::new(database_now_ms(&database).await?),
        )?;
        let materialized = database
            .store()
            .commit_logical_instance_materialization(exact_commit.clone())
            .await?;

        let session = open_v5_runner(&database, &fixture.tenant, 50_300).await?;
        let terminal_at = database_now_ms(&database).await?;
        let result = successful_job_result(materialized.attempt_id(), terminal_at);
        let result_bytes = serde_json::to_vec(&result)?;
        seed_successful_terminal_result(
            &database,
            &session,
            materialized.attempt_id(),
            &result_bytes,
            terminal_at,
            50_400,
        )
        .await?;

        let instance_observed_at = database_now_ms(&database).await?;
        let instance_claimed = match database
            .store()
            .claim_logical_instance_result(ClaimLogicalInstanceResult::new(
                LogicalInstanceResultTarget::new(
                    TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                    materialized.attempt_id(),
                )?,
                LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(50_500))?,
                UnixMillis::new(instance_observed_at),
                UnixMillis::new(instance_observed_at + 60_000),
            )?)
            .await?
        {
            LogicalInstanceResultClaimOutcome::Claimed(claimed) => claimed,
            other => return Err(format!("instance result was not ready: {other:?}").into()),
        };
        let instance_result = database
            .store()
            .commit_logical_instance_result(CommitLogicalInstanceResult::new(
                &instance_claimed,
                &result_bytes,
                &result,
                &prepared.encoded,
                &prepared.envelope,
                UnixMillis::new(instance_observed_at + 1_000),
            )?)
            .await?;
        wait_until_database_after(&database, instance_result.finalized_at().get()).await?;

        let job_observed_at = database_now_ms(&database).await?;
        let job_claimed = match database
            .store()
            .claim_logical_job_result(ClaimLogicalJobResult::new(
                LogicalJobResultTarget::new(
                    TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                    fixture.command.run_id(),
                    fixture.command.root_invocation_id(),
                    fixture.logical_job_id,
                )?,
                LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(50_600))?,
                UnixMillis::new(job_observed_at),
                UnixMillis::new(job_observed_at + 60_000),
            )?)
            .await?
        {
            LogicalJobResultClaimOutcome::Claimed(claimed) => claimed,
            other => return Err(format!("logical job result was not ready: {other:?}").into()),
        };
        let job_result = database
            .store()
            .commit_logical_job_result(CommitLogicalJobResult::new(
                &job_claimed,
                &fixture.plan_bytes,
                &fixture.plan,
                UnixMillis::new(job_observed_at + 1_000),
            )?)
            .await?;
        wait_until_database_after(&database, job_result.finalized_at().get()).await?;

        assert_materialization_receipt_replays(
            &database,
            exact_commit.clone(),
            &materialized,
            "after logical-job finalization",
        )
        .await?;

        let run_observed_at = database_now_ms(&database).await?;
        let run_claimed = database
            .store()
            .claim_logical_run_finalization(ClaimLogicalRunFinalization::new(
                LogicalRunFinalizationWorkerId::from_uuid(Uuid::from_u128(50_800))?,
                UnixMillis::new(run_observed_at),
                UnixMillis::new(run_observed_at + 60_000),
            )?)
            .await?
            .ok_or("terminal logical run was not ready for finalization")?;
        database
            .store()
            .commit_logical_run_finalization(CommitLogicalRunFinalization::new(
                &run_claimed,
                run_claimed.claim().claimed_at(),
            )?)
            .await?;
        assert_eq!(
            run_status(database.pool(), fixture.command.run_id()).await?,
            "completed"
        );

        assert_materialization_receipt_replays(
            &database,
            exact_commit.clone(),
            &materialized,
            "after logical-run finalization",
        )
        .await?;

        let forged_outputs_digest = [0xa5_u8; 32];
        let mut tamper = database.pool().begin().await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_results DISABLE TRIGGER USER",
        )
        .execute(&mut *tamper)
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_run_result_jobs DISABLE TRIGGER USER",
        )
        .execute(&mut *tamper)
        .await?;
        assert_eq!(
            sqlx::query(
                "UPDATE workflow_plan_v2_job_results SET outputs_digest = $2 WHERE logical_job_id = $1",
            )
            .bind(fixture.logical_job_id.as_uuid())
            .bind(forged_outputs_digest.as_slice())
            .execute(&mut *tamper)
            .await?
            .rows_affected(),
            1
        );
        assert_eq!(
            sqlx::query(
                "UPDATE workflow_plan_v2_run_result_jobs SET outputs_digest = $3 WHERE run_id = $1 AND logical_job_id = $2",
            )
            .bind(fixture.command.run_id().as_uuid())
            .bind(fixture.logical_job_id.as_uuid())
            .bind(forged_outputs_digest.as_slice())
            .execute(&mut *tamper)
            .await?
            .rows_affected(),
            1
        );
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_results ENABLE TRIGGER USER",
        )
        .execute(&mut *tamper)
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_run_result_jobs ENABLE TRIGGER USER",
        )
        .execute(&mut *tamper)
        .await?;
        tamper.commit().await?;

        assert!(matches!(
            database
                .store()
                .commit_logical_instance_materialization(exact_commit)
                .await,
            Err(LogicalMaterializationStoreError::Store(
                StoreError::CorruptData(_)
            ))
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn zero_instance_activation_creates_no_claim_job_attempt_or_legacy_edge() -> TestResult {
    run_with_database(|database| async move {
        let mut fixture = fixture(&database, "materialization-zero", 20_000).await?;
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &mut fixture, false).await?;
        let activated_claim = claim_activation(&database, &fixture, 20_100).await?;
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                activated_claim.claim().clone(),
                true,
                Vec::new(),
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;

        for table in [
            "workflow_plan_v2_instances",
            "workflow_plan_v2_materialization_claims",
            "workflow_plan_v2_concrete_jobs",
            "jobs",
            "job_dependencies",
        ] {
            let count: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                    .fetch_one(database.pool())
                    .await?;
            assert_eq!(count, 0, "zero-instance activation populated {table}");
        }
        let missing_observed_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(materialization_selection_request(
                    20_190,
                    20_200,
                    missing_observed_at,
                    60_000,
                ))
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Idle
        ));
        let reconciliation = database
            .store()
            .reconcile_run(
                fixture.command.run_id(),
                UnixMillis::new(database_now_ms(&database).await?),
            )
            .await?;
        assert_eq!(reconciliation.status(), WorkflowRunStatus::Queued);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn logical_concurrency_preemption_fences_unmaterialized_work() -> TestResult {
    run_with_database(|database| async move {
        let race =
            prepare_materialization_race_fixture(&database, "logical-preemption", 25_000).await?;
        let replacement = replacement_admission(&race.fixture, 0xd0, 1_200)?;
        database.store().admit_workflow(replacement.command).await?;

        let states: (String, String, String) = sqlx::query_as(
            r"
            SELECT run.status, marker.state, invocation.state
            FROM workflow_runs AS run
            JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
            JOIN workflow_plan_v2_invocations AS invocation
              ON invocation.run_id = marker.run_id
             AND invocation.id = marker.root_invocation_id
            WHERE run.id = $1
            ",
        )
        .bind(race.fixture.command.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            states,
            ("cancelled".into(), "cancelled".into(), "cancelled".into())
        );
        let cancellation_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_concurrency_cancellations WHERE run_id = $1",
        )
        .bind(race.fixture.command.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(cancellation_count, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn cancellation_first_rejects_a_waiting_materialization_without_partial_rows() -> TestResult {
    run_with_database(|database| async move {
        let race =
            prepare_materialization_race_fixture(&database, "materialization-cancel-first", 30_000)
                .await?;
        let replacement = replacement_admission(&race.fixture, 0xd1, 1_200)?;
        let expected_job_id = race.claimed.descriptor().expected_job_id();
        let expected_attempt_id = race.claimed.descriptor().expected_attempt_id();
        let commit = materialization_commit(&race)?;

        let mut gate = database.pool().begin().await?;
        let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *gate)
            .await?;
        sqlx::query("LOCK TABLE attempt_cancellation_intents IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *gate)
            .await?;

        let admission_store = database.store().clone();
        let admission =
            tokio::spawn(async move { admission_store.admit_workflow(replacement.command).await });
        let cancellation_pid =
            wait_for_backend_blocked_by(database.pool(), gate_pid, "FROM job_attempts AS attempt")
                .await?;

        let materialization_store = database.store().clone();
        let materialization = tokio::spawn(async move {
            materialization_store
                .commit_logical_instance_materialization(commit)
                .await
        });
        wait_for_backend_blocked_by(
            database.pool(),
            cancellation_pid,
            "FROM workflow_runs AS run",
        )
        .await?;
        gate.commit().await?;

        let admission_receipt = tokio::time::timeout(Duration::from_secs(5), admission).await???;
        assert_eq!(admission_receipt.run_id(), replacement.run_id);
        let materialization_result =
            tokio::time::timeout(Duration::from_secs(5), materialization).await??;
        assert!(matches!(
            materialization_result,
            Err(LogicalMaterializationStoreError::ClaimRejected)
        ));
        assert_eq!(
            run_status(database.pool(), race.fixture.command.run_id()).await?,
            "cancelled"
        );
        assert_eq!(
            row_count(database.pool(), "jobs", expected_job_id.as_uuid()).await?,
            0
        );
        assert_eq!(
            row_count(
                database.pool(),
                "job_attempts",
                expected_attempt_id.as_uuid(),
            )
            .await?,
            0
        );
        let replay_observed_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(materialization_selection_request(
                    30_191,
                    30_201,
                    replay_observed_at,
                    60_000,
                ))
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Idle
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn materialization_first_is_visible_to_waiting_cancellation_and_replays() -> TestResult {
    run_with_database(|database| async move {
        let race =
            prepare_materialization_race_fixture(&database, "materialization-commit-first", 40_000)
                .await?;
        let replacement = replacement_admission(&race.fixture, 0xd2, 1_200)?;
        let commit = materialization_commit(&race)?;
        let expected_attempt_id = race.claimed.descriptor().expected_attempt_id();

        let mut gate = database.pool().begin().await?;
        let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *gate)
            .await?;
        sqlx::query("LOCK TABLE workflow_plan_v2_concrete_jobs IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *gate)
            .await?;

        let materialization_store = database.store().clone();
        let commit_for_task = commit.clone();
        let materialization = tokio::spawn(async move {
            materialization_store
                .commit_logical_instance_materialization(commit_for_task)
                .await
        });
        let materialization_pid = wait_for_backend_blocked_by(
            database.pool(),
            gate_pid,
            "INSERT INTO workflow_plan_v2_concrete_jobs",
        )
        .await?;

        let admission_store = database.store().clone();
        let admission =
            tokio::spawn(async move { admission_store.admit_workflow(replacement.command).await });
        wait_for_backend_blocked_by(database.pool(), materialization_pid, "SELECT status").await?;
        gate.commit().await?;

        let materialized =
            tokio::time::timeout(Duration::from_secs(5), materialization).await???;
        assert!(!materialized.is_replay());
        let admission_receipt = tokio::time::timeout(Duration::from_secs(5), admission).await???;
        assert_eq!(admission_receipt.run_id(), replacement.run_id);
        assert_eq!(
            run_status(database.pool(), race.fixture.command.run_id()).await?,
            "cancelled"
        );
        assert_eq!(
            attempt_lifecycle(database.pool(), expected_attempt_id).await?,
            "cancelled"
        );
        let cancellation_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM attempt_cancellation_intents WHERE attempt_id = $1",
        )
        .bind(expected_attempt_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(cancellation_count, 1);

        let replay = database
            .store()
            .commit_logical_instance_materialization(commit)
            .await?;
        assert!(replay.is_replay());
        assert_eq!(replay.job_id(), materialized.job_id());
        let claim_replay_observed_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(materialization_selection_request(
                    40_191,
                    40_201,
                    claim_replay_observed_at,
                    60_000,
                ))
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Idle
        ));
        Ok(())
    })
    .await
}

async fn prepare_materialization_race_fixture(
    database: &TestDatabase,
    tenant: &str,
    namespace: u128,
) -> TestResult<MaterializationRaceFixture> {
    let mut fixture = fixture_with_concurrency(database, tenant, namespace, true).await?;
    seed_tenant(database, &fixture.tenant).await?;
    admit_authenticated_fixture(database, &mut fixture, false).await?;
    let activated_claim = claim_activation(database, &fixture, namespace + 100).await?;
    let prepared = prepared_instance(
        &fixture,
        &activated_claim,
        0,
        1,
        [0x7a; 32],
        JobAuthorityProfile::Standard,
    );
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            activated_claim.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    let expected_target = target(&fixture, prepared.activated.id());
    let consumed = select_materialization(database, namespace + 190, namespace + 200).await?;
    assert_eq!(consumed.selected().target(), &expected_target);
    let claimed = consumed.authority().clone();
    Ok(MaterializationRaceFixture {
        fixture,
        prepared,
        claimed,
    })
}

fn materialization_commit(
    race: &MaterializationRaceFixture,
) -> TestResult<CommitLogicalInstanceMaterialization> {
    Ok(CommitLogicalInstanceMaterialization::new(
        &race.claimed,
        &race.prepared.encoded,
        &race.prepared.envelope,
        &race.prepared.runtime_encoded,
        &race.prepared.runtime_context,
        race.claimed.claim().claimed_at(),
    )?)
}

fn replacement_admission(
    fixture: &Fixture,
    tag: u8,
    admitted_at: i64,
) -> TestResult<ReplacementAdmission> {
    let run_id = RunId::new();
    let job_id = JobId::new();
    let attempt_id = AttemptId::new();
    let job = AdmittedWorkflowJob::new(
        job_id,
        attempt_id,
        format!("replacement-{tag}"),
        format!("Replacement {tag}"),
        admission_object_with_media(
            format!("materialization/replacement-{tag}/job.json"),
            tag,
            "application/json",
        ),
        RoutingDocument::new(serde_json::to_string(&RunnerRequirements::default())?)?,
        Vec::new(),
    )?;
    let command = AdmitWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        WorkflowAdmissionIdempotency::operation(OperationId::new()),
        Sha256Digest::from_bytes([tag; 32]),
        fixture.command.repository().clone(),
        fixture.command.workflow_id(),
        fixture.command.workflow_path(),
        fixture.command.workflow_name(),
        fixture.command.git_ref(),
        WorkflowSnapshotId::from_uuid(Uuid::new_v4()),
        admission_object_with_media(
            format!("materialization/replacement-{tag}/source.yml"),
            tag.wrapping_add(1),
            "application/yaml",
        ),
        admission_object_with_media(
            format!("materialization/replacement-{tag}/plan.json"),
            tag.wrapping_add(2),
            "application/json",
        ),
        run_id,
        1,
        "push",
        admission_object_with_media(
            format!("materialization/replacement-{tag}/event.json"),
            tag.wrapping_add(3),
            "application/json",
        ),
        vec![tag; 20],
        vec![job],
        fixture.at(admitted_at),
    )
    .concurrency(Some(WorkflowConcurrency::new(
        MATERIALIZATION_RACE_GROUP,
        true,
    )?))
    .build()?;
    Ok(ReplacementAdmission { command, run_id })
}

async fn wait_for_backend_blocked_by(
    pool: &PgPool,
    blocking_backend_pid: i32,
    query_fragment: &str,
) -> TestResult<i32> {
    for _ in 0..500 {
        let waiting_backend_pid: Option<i32> = sqlx::query_scalar(
            r"
            SELECT pid
            FROM pg_stat_activity
            WHERE pid <> $1
              AND $1 = ANY(pg_blocking_pids(pid))
              AND query LIKE '%' || $2 || '%'
            ORDER BY pid
            LIMIT 1
            ",
        )
        .bind(blocking_backend_pid)
        .bind(query_fragment)
        .fetch_optional(pool)
        .await?;
        if let Some(waiting_backend_pid) = waiting_backend_pid {
            return Ok(waiting_backend_pid);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("backend did not block on expected {query_fragment} lock").into())
}

async fn run_status(pool: &PgPool, run_id: RunId) -> TestResult<String> {
    Ok(
        sqlx::query_scalar("SELECT status FROM workflow_runs WHERE id = $1")
            .bind(run_id.as_uuid())
            .fetch_one(pool)
            .await?,
    )
}

async fn attempt_lifecycle(pool: &PgPool, attempt_id: AttemptId) -> TestResult<String> {
    Ok(
        sqlx::query_scalar("SELECT lifecycle FROM job_attempts WHERE id = $1")
            .bind(attempt_id.as_uuid())
            .fetch_one(pool)
            .await?,
    )
}

async fn assert_materialization_receipt_replays(
    database: &TestDatabase,
    commit: CommitLogicalInstanceMaterialization,
    expected: &automata_ci_store::LogicalMaterializationReceipt,
    stage: &str,
) -> TestResult {
    let commit_replay = match database
        .store()
        .commit_logical_instance_materialization(commit)
        .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            return Err(format!("materialization replay {stage} failed: {error:?}").into());
        }
    };
    assert!(commit_replay.is_replay());
    assert_eq!(commit_replay.job_id(), expected.job_id());
    assert_eq!(commit_replay.attempt_id(), expected.attempt_id());
    assert_eq!(commit_replay.commit_digest(), expected.commit_digest());
    Ok(())
}

fn successful_job_result(attempt_id: AttemptId, completed_at: i64) -> JobResult {
    let result = JobResult::new(
        attempt_id,
        JobConclusion::Success,
        JobSecretExposure::ReadableSecret,
        UnixMillis::new(completed_at),
    );
    result.validate().expect("valid successful job result");
    result
}

async fn seed_successful_terminal_result(
    database: &TestDatabase,
    session: &RunnerSessionFence,
    attempt_id: AttemptId,
    result_bytes: &[u8],
    completed_at: i64,
    operation: u128,
) -> TestResult {
    let lease_id = Uuid::from_u128(operation + 1_000);
    let mut transaction = database.pool().begin().await?;
    let activated = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'running', fencing_token = 1, lease_id = $2,
            runner_id = $3, lease_issued_at_ms = $4,
            lease_expires_at_ms = $5, runner_session_id = $6,
            runner_session_epoch = $7, runner_generation = $8,
            runner_slot = 1, changed_at_ms = $4
        WHERE id = $1 AND lifecycle = 'queued'
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(lease_id)
    .bind(session.runner_id().as_uuid())
    .bind(completed_at)
    .bind(completed_at + 1_000)
    .bind(session.session_id().as_uuid())
    .bind(i64::try_from(session.session_epoch().get())?)
    .bind(i64::try_from(session.runner_generation().get())?)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    assert_eq!(activated, 1, "queued attempt must become active once");
    let inserted = sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, terminal_authority,
            runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, result_schema, result_size_bytes,
            result_digest, result_object_key, conclusion,
            completed_at_ms, committed_at_ms
        ) VALUES ($1,'runner',$2,$3,$4,$5,$6,1,$7,1,1,$8,$9,$10,'success',$11,$12)
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(session.session_id().as_uuid())
    .bind(Uuid::from_u128(operation))
    .bind(session.runner_id().as_uuid())
    .bind(i64::try_from(session.session_epoch().get())?)
    .bind(i64::try_from(session.runner_generation().get())?)
    .bind(lease_id)
    .bind(i64::try_from(result_bytes.len())?)
    .bind(Sha256::digest(result_bytes).as_slice())
    .bind(format!("materialization/terminal-{operation}.json"))
    .bind(completed_at)
    .bind(completed_at + 10)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    assert_eq!(inserted, 1, "terminal evidence must be inserted once");
    let transitioned = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'succeeded', lease_id = NULL, runner_id = NULL,
            lease_issued_at_ms = NULL, lease_expires_at_ms = NULL,
            runner_session_id = NULL, runner_session_epoch = NULL,
            runner_generation = NULL, runner_slot = NULL, changed_at_ms = $3
        WHERE id = $1 AND lifecycle = 'running' AND lease_id = $2
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(lease_id)
    .bind(completed_at + 10)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    assert_eq!(transitioned, 1, "active attempt must terminalize once");
    transaction.commit().await?;
    Ok(())
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
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

async fn row_count(pool: &PgPool, table: &'static str, id: Uuid) -> TestResult<i64> {
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM {table} WHERE id = $1"
    )))
    .bind(id)
    .fetch_one(pool)
    .await?)
}

async fn fixture(database: &TestDatabase, tenant: &str, namespace: u128) -> TestResult<Fixture> {
    fixture_with_concurrency(database, tenant, namespace, false).await
}

async fn fixture_with_concurrency(
    database: &TestDatabase,
    tenant: &str,
    namespace: u128,
    concurrency: bool,
) -> TestResult<Fixture> {
    let clock_origin_ms = database_now_ms(database).await?;
    let tenant_scope = TenantScope::from_authenticated_tenant_id(tenant)?;
    let manifest = materialization_manifest(tenant_scope.clone(), namespace)?;
    let github_repository_id = manifest.github_repository_id();
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("invocation");
    let logical_job_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("job");
    let plan = materialization_workflow_plan();
    let plan_bytes = serde_json::to_vec(&plan).expect("canonical logical workflow plan");
    let logical_job = AdmittedLogicalWorkflowJob::new(
        logical_job_id,
        WorkflowJobKey::new("build").expect("key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("logical job");
    let mut command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!("materialize-{namespace}"))
            .expect("idempotency"),
        Sha256Digest::from_bytes([0x40; 32]),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            github_repository_id.get().to_string(),
            "example",
            format!("project-{namespace}"),
        )
        .expect("repository"),
        workflow_id,
        ".github/workflows/ci.yml",
        "CI",
        "refs/heads/main",
        snapshot_id,
        admission_object(format!("materialization/{namespace}/source"), 0x11),
        admission_object_from_bytes(
            format!("materialization/{namespace}/plan"),
            &plan_bytes,
            LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE,
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(format!("materialization/{namespace}/event"), 0x13),
        vec![0x14; 20],
        vec![logical_job],
        UnixMillis::new(clock_origin_ms),
    )
    .base_context(runtime_context_object(
        format!("materialization/{namespace}/base-context.pb"),
        0x15,
    ));
    if concurrency {
        command = command.concurrency(Some(WorkflowConcurrency::new(
            MATERIALIZATION_RACE_GROUP,
            false,
        )?));
    }
    let command = command.build().expect("logical admission");
    Ok(Fixture {
        tenant: tenant.to_owned(),
        namespace,
        manifest,
        clock_origin_ms,
        command,
        logical_job_id,
        plan,
        plan_bytes,
    })
}

fn materialization_manifest(
    tenant_scope: TenantScope,
    namespace: u128,
) -> TestResult<GithubProviderManifest> {
    let connection_id = ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 20))?;
    let installation_id = ProviderInstallationId::new(u64::try_from(namespace + 30)?)?;
    let github_repository_id = ProviderRepositoryId::new(u64::try_from(namespace + 40)?)?;
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    Ok(GithubProviderManifest::new(
        tenant_scope,
        connection_id,
        installation_id,
        github_repository_id,
        GithubRepositoryName::new(format!("example/project-{namespace}"))?,
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(u64::try_from(namespace + 50)?)?,
        GithubServerServiceAppClientId::new(format!("Iv1.materialization-{namespace}"))?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x61; 32]),
        GithubServerServiceRevision::new(1)?,
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes(
            [0x62; 32],
        ))?,
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
    ))
}

fn materialization_workflow_plan() -> WorkflowPlan {
    let runner = LogicalRunnerTemplate::new(
        None,
        vec![materialization_located(CompiledValueTemplate::Literal(
            "linux".to_owned(),
        ))],
        materialization_span(),
    );
    let step = LogicalStepTemplate::builder(
        materialization_located(
            WorkflowStepKey::new("position/00000000").expect("workflow step key"),
        ),
        LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
            materialization_located(CompiledValueTemplate::Literal("true".to_owned())),
            None,
            None,
        ))),
        materialization_span(),
    )
    .build()
    .expect("logical step");
    let job = LogicalJobTemplate::builder(
        materialization_located(WorkflowJobKey::new("build").expect("workflow job key")),
        0,
        LogicalJobKind::Steps(StepJobTemplate::new(
            runner,
            vec![step],
            materialization_span(),
        )),
        materialization_span(),
    )
    .build()
    .expect("logical job");
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "github",
            "materialization.yml",
            PlanSourceOrigin::Memory {
                name: "materialization.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
        vec![job],
        materialization_span(),
    )
    .build()
    .expect("logical workflow plan")
}

fn materialization_span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "materialization.yml",
        PlanSourceLocation::new(0, 1, 1).expect("source location"),
        PlanSourceLocation::new(1, 1, 2).expect("source location"),
    )
    .expect("source span")
}

fn materialization_located<T>(value: T) -> Located<T> {
    Located::new(value, materialization_span())
}

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Materialization test', 1, 1)",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn admit_authenticated_fixture(
    database: &TestDatabase,
    fixture: &mut Fixture,
    publish_publicly: bool,
) -> TestResult {
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
                Sha256Digest::from_bytes([0x63; 32]),
            )?,
            now,
        )?)
        .await?;

    if publish_publicly {
        let updated = sqlx::query(
            r"
            UPDATE repository_publication_policies
            SET revision = revision + 1, dashboard_audience = 'public',
                log_audience = 'public', artifact_audience = 'public',
                updated_at_ms = $3
            WHERE tenant_id = $1 AND repository_id = $2
            ",
        )
        .bind(&fixture.tenant)
        .bind(fixture.command.repository().id().as_uuid())
        .bind(database_now_ms(database).await?)
        .execute(database.pool())
        .await?;
        assert_eq!(updated.rows_affected(), 1);
    }

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
                    format!("materialization-{}", fixture.namespace),
                )?,
                fixture.command.request_digest(),
                fixture.command.event().clone(),
                accepted_at,
            )?,
            ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace + 60)?)?,
            ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace + 60)?)?,
            GithubCheckHeadSha::new([0x14; 20])?,
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
    if let Some(actor) = command.actor() {
        builder = builder.actor(actor);
    }
    if let Some(display_title) = command.display_title() {
        builder = builder.display_title(display_title);
    }
    if let Some(commit_subject) = command.commit_subject() {
        builder = builder.commit_subject(commit_subject);
    }
    if let Some(base_context) = command.base_context() {
        builder = builder.base_context(base_context.clone());
    }
    builder = builder.concurrency(command.concurrency().cloned());
    Ok(builder.build()?)
}

async fn load_attempt_safety(
    database: &TestDatabase,
    attempt_id: automata_ci_core::AttemptId,
) -> TestResult<DurableAttemptSafety> {
    let row: (String, String, String, String, String, i32, i64) = sqlx::query_as(
        r"
        SELECT secret_exposure_class, raw_log_disposition,
               requested_log_visibility, effective_log_visibility,
               output_safety_reason, output_safety_schema, classified_at_ms
        FROM job_attempts
        WHERE id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    Ok(DurableAttemptSafety {
        secret_exposure: row.0,
        raw_log_disposition: row.1,
        requested_visibility: row.2,
        effective_visibility: row.3,
        reason: row.4,
        schema: row.5,
        classified_at: row.6,
    })
}

fn standard_public_attempt_safety(classified_at: i64) -> DurableAttemptSafety {
    DurableAttemptSafety {
        secret_exposure: "readable_secret".to_owned(),
        raw_log_disposition: "persist".to_owned(),
        requested_visibility: "public".to_owned(),
        effective_visibility: "private".to_owned(),
        reason: "secret_exposure".to_owned(),
        schema: 2,
        classified_at,
    }
}

async fn open_v5_runner(
    database: &TestDatabase,
    tenant: &str,
    runner_identity: u128,
) -> TestResult<RunnerSessionFence> {
    let observed_at = database_now_ms(database).await?;
    let runner_id = RunnerId::from_uuid(Uuid::from_u128(runner_identity));
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    );
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots, status,
            desired_state, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'materialization-runner', 'materialization-runner',
                $3::jsonb, 1, 'online', 'active', 1, 1)
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(tenant)
    .bind(serde_json::to_value(&capabilities)?)
    .execute(database.pool())
    .await?;
    let capability_snapshot = RoutingDocument::new(serde_json::to_string(&capabilities)?)?;
    let session = database
        .store()
        .open_session(OpenRunnerSession::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(1)?,
            RunnerProtocolVersion::new(4)?,
            JobIrVersion::current(),
            capability_snapshot,
            UnixMillis::new(observed_at),
        ))
        .await?;
    Ok(session.fence())
}

async fn claim_activation(
    database: &TestDatabase,
    fixture: &Fixture,
    owner: u128,
) -> TestResult<ClaimedLogicalJobActivation> {
    let preparation = match select_orchestration(database, owner + 10_000, owner + 20_000).await? {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => {
            assert_eq!(
                claimed.claim().target().logical_job_id(),
                fixture.logical_job_id
            );
            claimed
        }
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            return Err(format!("expected selected preparation, got {authority:?}").into());
        }
    };
    let bound_at = database_now_ms(database).await?;
    let prepared = database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            preparation.descriptor().clone(),
            preparation.claim().clone(),
            preparation.descriptor().base_context().clone(),
            runtime_context_object(format!("materialization/{owner}/needs-context.pb"), 0x52),
            UnixMillis::new(bound_at),
        )?)
        .await?;
    match select_orchestration(database, owner, owner + 30_000).await? {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
            assert_eq!(claimed.claim().logical_job_id(), fixture.logical_job_id);
            assert_eq!(claimed.claim().input_digest(), prepared.input_digest());
            Ok(claimed)
        }
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            Err(format!("expected selected activation, got {authority:?}").into())
        }
    }
}

async fn select_orchestration(
    database: &TestDatabase,
    owner: u128,
    selection: u128,
) -> TestResult<ConsumedLogicalJobOrchestrationAuthority> {
    let observed_at = database_now_ms(database).await?;
    let request = ClaimNextLogicalJobOrchestration::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection))?,
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(owner))?,
        UnixMillis::new(observed_at),
        60_000,
    )?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(request)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => {
            return Err(format!("logical orchestration was not selected: {outcome:?}").into());
        }
    };
    let consumed = database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?;
    Ok(consumed.authority().clone())
}

fn prepared_instance(
    fixture: &Fixture,
    claimed: &ClaimedLogicalJobActivation,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: [u8; 32],
    authority_profile: JobAuthorityProfile,
) -> PreparedInstance {
    let job_id = deterministic_job_id(
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
        matrix_index,
        matrix_total,
        matrix_digest,
    );
    let identity = JobInstanceIdentity::new(
        claimed.logical_key().as_str(),
        matrix_index,
        matrix_total,
        Sha256Digest::from_bytes(matrix_digest),
    )
    .expect("matrix identity");
    let (runtime_context, runtime_encoded, runtime) =
        prepared_runtime_context(matrix_index, matrix_total);
    let event = claimed.event();
    let execution = claimed.execution();
    let workspace = format!("/srv/work/project/{matrix_index}");
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
    let mut job = JobIr::new(
        job_id,
        fixture.command.run_id(),
        format!("Build {matrix_index}"),
        RunnerRequirements::default(),
        identity.clone(),
        false,
        vec![step],
    )
    .with_authority_profile(authority_profile);
    if authority_profile == JobAuthorityProfile::CredentialFree {
        job = job.with_permission_request(JobPermissionRequest::mapping([]));
    }
    let job_execution = JobExecutionContext::new(
        execution.workflow_name(),
        execution.git_ref(),
        &workspace,
        content_reference(event),
        activation_reference(&runtime),
    )
    .with_run_id_alias(execution.run_id_alias())
    .with_run_number(execution.run_number())
    .with_run_attempt(execution.run_attempt());
    let envelope = JobIrEnvelope::new(
        execution.workflow_id(),
        JobSource::new(
            "github",
            "example/project",
            "0123456789abcdef",
            ".github/workflows/ci.yml",
            "push",
        ),
        job_execution,
        job,
    );
    envelope.validate().expect("current JobIR");
    let encoded = serde_json::to_vec(&envelope).expect("synthetic encoded JobIR");
    let activated = ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        workspace,
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new(format!("job-ir/{matrix_index}.pb")).expect("JobIR key"),
            u64::try_from(encoded.len()).expect("size"),
        )
        .expect("JobIR descriptor"),
        runtime,
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

fn prepared_runtime_context(
    matrix_index: u32,
    matrix_total: u32,
) -> (JobRuntimeContext, Vec<u8>, LogicalActivationObject) {
    let empty = ContextValue::object(BTreeMap::new()).expect("empty context");
    let runtime_context = JobRuntimeContext::new(
        empty.clone(),
        empty.clone(),
        empty,
        StrategyContext::new(false, matrix_index, matrix_total, matrix_total).expect("strategy"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("runtime context");
    let runtime_encoded =
        serde_json::to_vec(&runtime_context).expect("synthetic encoded runtime context");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes(Sha256::digest(&runtime_encoded).into()),
        ObjectKey::new(format!("contexts/{matrix_index}.pb")).expect("runtime key"),
        u64::try_from(runtime_encoded.len()).expect("runtime size"),
    )
    .expect("runtime context");
    (runtime_context, runtime_encoded, runtime)
}

fn target(
    fixture: &Fixture,
    instance_id: LogicalWorkflowInstanceId,
) -> LogicalInstanceMaterializationTarget {
    LogicalInstanceMaterializationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant).expect("tenant"),
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
        instance_id,
    )
    .expect("target")
}

async fn publish_single_materialization_candidate(
    database: &TestDatabase,
    fixture: &mut Fixture,
    activation_owner: u128,
    matrix_digest: [u8; 32],
) -> TestResult<PreparedInstance> {
    seed_tenant(database, &fixture.tenant).await?;
    admit_authenticated_fixture(database, fixture, true).await?;
    let activation = claim_activation(database, fixture, activation_owner).await?;
    let prepared = prepared_instance(
        fixture,
        &activation,
        0,
        1,
        matrix_digest,
        JobAuthorityProfile::Standard,
    );
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            activation.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    Ok(prepared)
}

fn materialization_selection_request(
    selection: u128,
    owner: u128,
    observed_at: i64,
    duration_ms: i64,
) -> ClaimNextLogicalInstanceMaterialization {
    ClaimNextLogicalInstanceMaterialization::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection)).expect("selection"),
        LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(owner))
            .expect("materialization worker"),
        UnixMillis::new(observed_at),
        duration_ms,
    )
    .expect("materialization selection request")
}

fn expect_selected_materialization(
    outcome: LogicalInstanceMaterializationSelectionOutcome,
) -> automata_ci_store::SelectedLogicalInstanceMaterialization {
    match outcome {
        LogicalInstanceMaterializationSelectionOutcome::Selected(selected) => selected,
        other => panic!("expected materialization selection, got {other:?}"),
    }
}

async fn consume_materialization(
    database: &TestDatabase,
    selected: automata_ci_store::SelectedLogicalInstanceMaterialization,
) -> TestResult<ConsumedSelectedLogicalInstanceMaterialization> {
    Ok(database
        .store()
        .consume_selected_logical_instance_materialization(
            ConsumeSelectedLogicalInstanceMaterialization::new(selected),
        )
        .await?)
}

async fn select_materialization(
    database: &TestDatabase,
    selection: u128,
    owner: u128,
) -> TestResult<ConsumedSelectedLogicalInstanceMaterialization> {
    let observed_at = database_now_ms(database).await?;
    let selected = expect_selected_materialization(
        database
            .store()
            .claim_next_logical_instance_materialization(materialization_selection_request(
                selection,
                owner,
                observed_at,
                60_000,
            ))
            .await?,
    );
    consume_materialization(database, selected).await
}

fn admission_object(key: String, digest: u8) -> AdmissionObject {
    admission_object_with_media(key, digest, "application/json")
}

fn admission_object_with_media(key: String, digest: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("object key"),
        512,
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

fn admission_object_from_bytes(key: String, bytes: &[u8], media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        ObjectKey::new(key).expect("object key"),
        u64::try_from(bytes.len()).expect("object size"),
        media_type,
    )
    .expect("admission object")
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

fn deterministic_job_id(
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: [u8; 32],
) -> JobId {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.workflow-service.logical-job-id.v1\0");
    hasher.update(run_id.as_uuid().as_bytes());
    hasher.update(invocation_id.as_uuid().as_bytes());
    hasher.update(logical_job_id.as_uuid().as_bytes());
    hasher.update(matrix_index.to_be_bytes());
    hasher.update(matrix_total.to_be_bytes());
    hasher.update(matrix_digest);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    JobId::from_uuid(Uuid::from_bytes(bytes))
}
