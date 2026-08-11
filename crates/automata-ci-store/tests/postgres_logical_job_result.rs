#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use std::collections::BTreeMap;

use automata_ci_core::{
    Architecture, CompiledValueTemplate, ContextValue, JobAuthorityProfile, JobConclusion,
    JobContentReference, JobExecutionContext, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope,
    JobIrVersion, JobOutputDefinition, JobResult, JobResultOutput, JobRuntimeContext,
    JobSecretExposure, JobSource, Located, LogicalJobKind, LogicalJobOutputDefinition,
    LogicalJobOutputSource, LogicalJobTemplate, LogicalOutputMergePolicy, LogicalRunStepTemplate,
    LogicalRunnerTemplate, LogicalStepKind, LogicalStepTemplate, MatrixAxis, MatrixAxisValues,
    MatrixPatchSet, MatrixTemplate, MatrixValue, MatrixValueTemplate, OperatingSystem,
    OutputSensitivity, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, RunId,
    RunValueTemplates, RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    StepJobTemplate, StrategyContext, UnixMillis, ValueTemplate, WorkflowEventProvenance,
    WorkflowId, WorkflowJobKey, WorkflowOutputKey, WorkflowPlan, WorkflowSourceProvenance,
    WorkflowStepKey, WorkflowStrategyTemplate,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation, ClaimLogicalInstanceResult,
    ClaimLogicalJobResult, ClaimNextLogicalInstanceMaterialization,
    ClaimNextLogicalJobOrchestration, ClaimNextLogicalJobResult, ClaimProviderDelivery,
    ClaimedLogicalInstanceMaterialization, ClaimedLogicalInstanceResult,
    ClaimedLogicalJobActivation, ClaimedLogicalJobResult, CommitLogicalInstanceMaterialization,
    CommitLogicalInstanceResult, CommitLogicalJobResult,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, EnsureGithubServerServiceAuthority,
    GithubCheckHeadSha, GithubCheckName, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    LogicalActivationObject, LogicalActivationPreparationStore as _,
    LogicalActivationPreparationTarget, LogicalActivationRepository as _,
    LogicalActivationWorkerId, LogicalInstanceMaterializationSelectionOutcome,
    LogicalInstanceMaterializationTarget, LogicalInstanceResultClaimOutcome,
    LogicalInstanceResultRepository as _, LogicalInstanceResultTarget,
    LogicalInstanceResultWorkerId, LogicalJobOrchestrationSelectionOutcome,
    LogicalJobResultClaimNextOutcome, LogicalJobResultClaimOutcome,
    LogicalJobResultRepository as _, LogicalJobResultSelectionId, LogicalJobResultStoreError,
    LogicalJobResultTarget, LogicalJobResultWorkerId, LogicalMaterializationRepository as _,
    LogicalMaterializationWorkerId, LogicalWorkSelectionId, LogicalWorkSelectionRepository as _,
    LogicalWorkflowAdmissionRepository as _, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, OpenRunnerSession, ProviderConnectionId,
    ProviderDeliveryClaimOwnerId, ProviderDeliveryIdentity, ProviderDeliveryRepository as _,
    ProviderInstallationId, ProviderRepositoryCoordinates, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, PublishLogicalJobActivation,
    RoutingDocument, RunnerGeneration, RunnerProtocolVersion, RunnerSessionFence,
    RunnerSessionRepository as _, StoreError, TenantScope, WorkflowAdmissionIdempotency,
    WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

#[derive(Clone)]
struct Fixture {
    tenant: String,
    namespace: u128,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    logical_job_id: LogicalWorkflowJobId,
    plan: WorkflowPlan,
    plan_bytes: Vec<u8>,
}

struct PreparedInstance {
    activated: ActivatedLogicalInstanceDescriptor,
    envelope: JobIrEnvelope,
    encoded: Vec<u8>,
    runtime_context: JobRuntimeContext,
    runtime_encoded: Vec<u8>,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn logical_result_is_ordered_fenced_replayable_and_terminal() -> TestResult {
    run_with_database(|database| async move {
        const INSTANCE_RESULT_CLAIM_MILLIS: i64 = 60_000;

        let idle_observed_at = database_now_ms(&database).await?;
        let idle_request = ClaimNextLogicalJobResult::new(
            LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(90_590))?,
            LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(90_591))?,
            UnixMillis::new(idle_observed_at),
            UnixMillis::new(idle_observed_at + 60_000),
        )?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left_idle, right_idle) = tokio::join!(
            left_store.claim_next_logical_job_result(idle_request.clone()),
            right_store.claim_next_logical_job_result(idle_request.clone()),
        );
        assert!(matches!(left_idle?, LogicalJobResultClaimNextOutcome::Idle));
        assert!(matches!(right_idle?, LogicalJobResultClaimNextOutcome::Idle));

        let fixture = fixture("logical-job-result-live", 90_000);
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &fixture).await?;
        let activation = claim_activation(&database, &fixture, 90_100).await?;
        let prepared = [
            prepared_instance(&fixture, &activation, 0),
            prepared_instance(&fixture, &activation, 1),
        ];
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                activation.claim().clone(),
                true,
                prepared
                    .iter()
                    .map(|instance| instance.activated.clone())
                    .collect(),
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;

        let mut materialized = Vec::new();
        for (index, instance) in prepared.iter().enumerate() {
            let claimed = select_materialization(
                &database,
                LogicalInstanceMaterializationTarget::new(
                    TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                    fixture.command.run_id(),
                    fixture.command.root_invocation_id(),
                    fixture.logical_job_id,
                    instance.activated.id(),
                )?,
                90_200 + u128::try_from(index)?,
            )
            .await?;
            materialized.push(
                database
                    .store()
                    .commit_logical_instance_materialization(
                        CommitLogicalInstanceMaterialization::new(
                            &claimed,
                            &instance.encoded,
                            &instance.envelope,
                            &instance.runtime_encoded,
                            &instance.runtime_context,
                            UnixMillis::new(database_now_ms(&database).await?),
                        )?,
                    )
                    .await?,
            );
        }

        let session = open_runner(&database, &fixture.tenant, 90_300).await?;
        let first_terminal_completed_at = database_now_ms(&database).await?;
        let second_terminal_completed_at = first_terminal_completed_at + 20;
        let results = [
            job_result(
                materialized[0].attempt_id(),
                second_terminal_completed_at,
            ),
            job_result(
                materialized[1].attempt_id(),
                first_terminal_completed_at,
            ),
        ];
        let result_bytes = [
            serde_json::to_vec(&results[0])?,
            serde_json::to_vec(&results[1])?,
        ];

        // Matrix index one commits first. An exact insert retry must not run
        // the AFTER-INSERT ordinal allocator or consume another value.
        seed_terminal_result(
            &database,
            &session,
            materialized[1].attempt_id(),
            &result_bytes[1],
            first_terminal_completed_at,
            90_400,
        )
        .await?;
        let first_ordinal = terminal_ordinal(&database, materialized[1].attempt_id()).await?;
        assert_eq!(first_ordinal, 1);
        seed_terminal_result(
            &database,
            &session,
            materialized[1].attempt_id(),
            &result_bytes[1],
            first_terminal_completed_at,
            90_400,
        )
        .await?;
        assert_eq!(
            terminal_counter(&database, fixture.logical_job_id).await?,
            1,
            "exact terminal-row replay must not consume another ordinal"
        );
        assert!(
            sqlx::query(
                "UPDATE workflow_plan_v2_job_terminal_counters SET last_ordinal = last_ordinal + 1 WHERE logical_job_id = $1",
            )
            .bind(fixture.logical_job_id.as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "only the terminal-row trigger may advance the server ordinal"
        );
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_job_terminal_counters WHERE logical_job_id = $1",
            )
            .bind(fixture.logical_job_id.as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "the retained terminal ordinal counter cannot be removed"
        );
        wait_until_database_after(&database, second_terminal_completed_at).await?;
        seed_terminal_result(
            &database,
            &session,
            materialized[0].attempt_id(),
            &result_bytes[0],
            second_terminal_completed_at,
            90_401,
        )
        .await?;
        assert_eq!(
            terminal_ordinal(&database, materialized[0].attempt_id()).await?,
            2
        );

        let mut instance_commits = Vec::new();
        let instance_projection_observed_at = database_now_ms(&database).await?;
        for (claim_order, index) in [1_usize, 0_usize].into_iter().enumerate() {
            let claimed_at = instance_projection_observed_at + i64::try_from(claim_order)?;
            let claimed = expect_instance_result_claimed(
                database
                    .store()
                    .claim_logical_instance_result(ClaimLogicalInstanceResult::new(
                        LogicalInstanceResultTarget::new(
                            TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                            materialized[index].attempt_id(),
                        )?,
                        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(
                            90_500 + u128::try_from(index)?,
                        ))?,
                        UnixMillis::new(claimed_at),
                        UnixMillis::new(claimed_at + INSTANCE_RESULT_CLAIM_MILLIS),
                    )?)
                    .await?,
            );
            assert_eq!(
                claimed.descriptor().terminal_ordinal().get(),
                if index == 1 { 1 } else { 2 }
            );
            instance_commits.push(CommitLogicalInstanceResult::new(
                &claimed,
                &result_bytes[index],
                &results[index],
                &prepared[index].encoded,
                &prepared[index].envelope,
                UnixMillis::new(claimed_at + 500),
            )?);
        }
        let partial_target = LogicalJobResultTarget::new(
            TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.logical_job_id,
        )?;
        let partial_observed_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    partial_target,
                    90_590,
                    partial_observed_at,
                    partial_observed_at + 3_000,
                ))
                .await?,
            LogicalJobResultClaimOutcome::NotReady
        ));
        let second_commit = instance_commits.pop().expect("matrix zero commit");
        let first_commit = instance_commits.pop().expect("matrix one commit");
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.commit_logical_instance_result(first_commit),
            right_store.commit_logical_instance_result(second_commit),
        );
        let instance_receipts = [left?, right?];
        assert_eq!(instance_receipts.len(), 2);
        let due_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_job_result_due WHERE logical_job_id = $1",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(due_count, 1);
        let tamper_claim_observed_at = database_now_ms(&database).await?;
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_job_result_due WHERE logical_job_id = $1",
            )
            .bind(fixture.logical_job_id.as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "the trigger-authoritative job due row cannot be deleted"
        );
        let original_outputs_digest: Vec<u8> = sqlx::query_scalar(
            "SELECT outputs_digest FROM workflow_plan_v2_instance_results WHERE instance_id = $1",
        )
        .bind(prepared[0].activated.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instance_results DISABLE TRIGGER workflow_plan_v2_instance_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_plan_v2_instance_results SET outputs_digest = $2 WHERE instance_id = $1",
        )
        .bind(prepared[0].activated.id().as_uuid())
        .bind(vec![0xA5_u8; 32])
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instance_results ENABLE TRIGGER workflow_plan_v2_instance_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        assert!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    LogicalJobResultTarget::new(
                        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                        fixture.command.run_id(),
                        fixture.command.root_invocation_id(),
                        fixture.logical_job_id,
                    )?,
                    90_589,
                    tamper_claim_observed_at,
                    tamper_claim_observed_at + 3_000,
                ))
                .await
                .is_err(),
            "a stored output digest cannot launder different child rows"
        );
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instance_results DISABLE TRIGGER workflow_plan_v2_instance_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_plan_v2_instance_results SET outputs_digest = $2 WHERE instance_id = $1",
        )
        .bind(prepared[0].activated.id().as_uuid())
        .bind(original_outputs_digest)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instance_results ENABLE TRIGGER workflow_plan_v2_instance_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        let original_commit_digest: Vec<u8> = sqlx::query_scalar(
            "SELECT commit_digest FROM workflow_plan_v2_instance_results WHERE instance_id = $1",
        )
        .bind(prepared[0].activated.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instance_results DISABLE TRIGGER workflow_plan_v2_instance_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_plan_v2_instance_results SET commit_digest = $2 WHERE instance_id = $1",
        )
        .bind(prepared[0].activated.id().as_uuid())
        .bind(vec![0x5A_u8; 32])
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instance_results ENABLE TRIGGER workflow_plan_v2_instance_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        assert!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    LogicalJobResultTarget::new(
                        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                        fixture.command.run_id(),
                        fixture.command.root_invocation_id(),
                        fixture.logical_job_id,
                    )?,
                    90_587,
                    tamper_claim_observed_at,
                    tamper_claim_observed_at + 3_000,
                ))
                .await
                .is_err(),
            "a stored instance commit digest cannot launder altered root evidence"
        );
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instance_results DISABLE TRIGGER workflow_plan_v2_instance_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_plan_v2_instance_results SET commit_digest = $2 WHERE instance_id = $1",
        )
        .bind(prepared[0].activated.id().as_uuid())
        .bind(original_commit_digest)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instance_results ENABLE TRIGGER workflow_plan_v2_instance_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        let original_workspace: String = sqlx::query_scalar(
            "SELECT workspace FROM workflow_plan_v2_instances WHERE id = $1",
        )
        .bind(prepared[0].activated.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instances DISABLE TRIGGER workflow_plan_v2_instances_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query("UPDATE workflow_plan_v2_instances SET workspace = $2 WHERE id = $1")
            .bind(prepared[0].activated.id().as_uuid())
            .bind("/tampered-activation-workspace")
            .execute(database.pool())
            .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instances ENABLE TRIGGER workflow_plan_v2_instances_reject_update",
        )
        .execute(database.pool())
        .await?;
        assert!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    LogicalJobResultTarget::new(
                        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                        fixture.command.run_id(),
                        fixture.command.root_invocation_id(),
                        fixture.logical_job_id,
                    )?,
                    90_588,
                    tamper_claim_observed_at,
                    tamper_claim_observed_at + 3_000,
                ))
                .await
                .is_err(),
            "a stored publication digest cannot launder altered instance descriptors"
        );
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instances DISABLE TRIGGER workflow_plan_v2_instances_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query("UPDATE workflow_plan_v2_instances SET workspace = $2 WHERE id = $1")
            .bind(prepared[0].activated.id().as_uuid())
            .bind(original_workspace)
            .execute(database.pool())
            .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instances ENABLE TRIGGER workflow_plan_v2_instances_reject_update",
        )
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(idle_request.clone())
                .await?,
            LogicalJobResultClaimNextOutcome::Idle
        ));

        let target = LogicalJobResultTarget::new(
            TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.logical_job_id,
        )?;
        let available_at: i64 = sqlx::query_scalar(
            "SELECT available_at_ms FROM workflow_plan_v2_job_result_due WHERE logical_job_id = $1",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        wait_until_database_after(&database, available_at).await?;
        let first_observed_at = database_now_ms(&database).await?;
        let first_expires_at = first_observed_at + 3_000;
        let first_request = ClaimNextLogicalJobResult::new(
            LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(90_599))?,
            LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(90_600))?,
            UnixMillis::new(first_observed_at),
            UnixMillis::new(first_expires_at),
        )?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.claim_next_logical_job_result(first_request.clone()),
            right_store.claim_next_logical_job_result(first_request.clone()),
        );
        let (first, replay) = match (left?, right?) {
            (
                LogicalJobResultClaimNextOutcome::Claimed(left),
                LogicalJobResultClaimNextOutcome::Claimed(right),
            ) if left.claim() == right.claim() && left.is_replay() != right.is_replay() => {
                if left.is_replay() {
                    (right, left)
                } else {
                    (left, right)
                }
            }
            outcomes => panic!("equal-ID job claims must replay exactly: {outcomes:?}"),
        };
        assert_eq!(first.claim().generation().get(), 1);
        assert!(replay.is_replay());
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(ClaimNextLogicalJobResult::new(
                    first_request.selection_id(),
                    LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(90_698))?,
                    first_request.observed_at(),
                    first_request.expires_at(),
                )?)
                .await,
            Err(LogicalJobResultStoreError::SelectionConflict)
        ));
        assert!(matches!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    target.clone(),
                    90_601,
                    first_observed_at + 100,
                    first_expires_at + 100,
                ))
                .await?,
            LogicalJobResultClaimOutcome::Busy
        ));
        let stale_commit = CommitLogicalJobResult::new(
            &first,
            &fixture.plan_bytes,
            &fixture.plan,
            UnixMillis::new(first_observed_at + 200),
        )?;
        wait_until_database_after(&database, first_expires_at).await?;
        let takeover_observed_at = database_now_ms(&database).await?;
        let takeover = expect_job_result_claimed(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    target.clone(),
                    90_602,
                    takeover_observed_at,
                    takeover_observed_at + 3_000,
                ))
                .await?,
        );
        assert_eq!(takeover.claim().generation().get(), 2);
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(first_request)
                .await,
            Err(LogicalJobResultStoreError::SelectionExpired)
        ));
        assert!(matches!(
            database
                .store()
                .commit_logical_job_result(stale_commit)
                .await,
            Err(LogicalJobResultStoreError::ClaimRejected)
        ));

        let current_commit = CommitLogicalJobResult::new(
            &takeover,
            &fixture.plan_bytes,
            &fixture.plan,
            UnixMillis::new(takeover_observed_at + 500),
        )?;
        assert_eq!(current_commit.outputs()[0].name().as_str(), "artifact");
        assert_eq!(current_commit.outputs()[0].public_value(), None);
        assert_eq!(
            current_commit.outputs()[0].sensitivity(),
            OutputSensitivity::SecretDerived
        );
        assert_eq!(current_commit.outputs()[1].name().as_str(), "missing");
        assert_eq!(current_commit.outputs()[1].public_value(), Some(""));
        assert_eq!(current_commit.outputs()[2].name().as_str(), "private");
        assert_eq!(current_commit.outputs()[2].public_value(), None);

        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.commit_logical_job_result(current_commit.clone()),
            right_store.commit_logical_job_result(current_commit),
        );
        let left = left?;
        let right = right?;
        assert_ne!(left.is_replay(), right.is_replay());
        assert_eq!(left.commit_digest(), right.commit_digest());
        assert_eq!(left.output_count(), 3);
        let due_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_job_result_due WHERE logical_job_id = $1",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(due_count, 0, "finalization removes the bounded due row");
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_job_result_claims WHERE logical_job_id = $1",
            )
            .bind(fixture.logical_job_id.as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "finalized logical-job fences cannot be deleted"
        );
        assert!(matches!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    target.clone(),
                    90_603,
                    takeover_observed_at + 600,
                    takeover_observed_at + 3_100,
                ))
                .await?,
            LogicalJobResultClaimOutcome::Finalized(receipt)
                if receipt.is_replay() && receipt.commit_digest() == left.commit_digest()
        ));

        let state: String = sqlx::query_scalar(
            "SELECT state FROM workflow_plan_v2_jobs WHERE id = $1",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(state, "completed");
        let outputs: Vec<(String, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT output_name, sensitivity, public_value
            FROM workflow_plan_v2_job_result_outputs
            WHERE logical_job_id = $1 ORDER BY output_name COLLATE "C"
            "#,
        )
        .bind(fixture.logical_job_id.as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(
            outputs,
            vec![
                (
                    "artifact".to_owned(),
                    "secret_derived".to_owned(),
                    None,
                ),
                ("missing".to_owned(), "public".to_owned(), Some(String::new())),
                ("private".to_owned(), "secret_derived".to_owned(), None),
            ]
        );

        let original_claim_started_at: i64 = sqlx::query_scalar(
            "SELECT claim_started_at_ms FROM workflow_plan_v2_job_results WHERE logical_job_id = $1",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_results DISABLE TRIGGER workflow_plan_v2_job_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_plan_v2_job_results SET claim_started_at_ms = $2 WHERE logical_job_id = $1",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .bind(original_claim_started_at + 1)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_results ENABLE TRIGGER workflow_plan_v2_job_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        let corrupt_replay_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    target.clone(),
                    90_604,
                    corrupt_replay_at,
                    corrupt_replay_at + 3_000,
                ))
                .await,
            Err(LogicalJobResultStoreError::Store(StoreError::CorruptData(_)))
        ));
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_results DISABLE TRIGGER workflow_plan_v2_job_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_plan_v2_job_results SET claim_started_at_ms = $2 WHERE logical_job_id = $1",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .bind(original_claim_started_at)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_results ENABLE TRIGGER workflow_plan_v2_job_results_reject_update",
        )
        .execute(database.pool())
        .await?;

        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_result_outputs DISABLE TRIGGER workflow_plan_v2_job_result_outputs_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_plan_v2_job_result_outputs SET public_value = 'tampered' WHERE logical_job_id = $1 AND output_name = 'missing'",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_result_outputs ENABLE TRIGGER workflow_plan_v2_job_result_outputs_reject_update",
        )
        .execute(database.pool())
        .await?;
        let corrupt_output_replay_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    target.clone(),
                    90_605,
                    corrupt_output_replay_at,
                    corrupt_output_replay_at + 3_000,
                ))
                .await,
            Err(LogicalJobResultStoreError::Store(StoreError::CorruptData(_)))
        ));
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_result_outputs DISABLE TRIGGER workflow_plan_v2_job_result_outputs_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE workflow_plan_v2_job_result_outputs SET public_value = '' WHERE logical_job_id = $1 AND output_name = 'missing'",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_result_outputs ENABLE TRIGGER workflow_plan_v2_job_result_outputs_reject_update",
        )
        .execute(database.pool())
        .await?;

        assert!(
            sqlx::query(
                "UPDATE workflow_plan_v2_job_results SET effective_conclusion = 'failure' WHERE logical_job_id = $1",
            )
            .bind(fixture.logical_job_id.as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "final logical-job evidence must be immutable"
        );
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_job_result_instances WHERE logical_job_id = $1",
            )
            .bind(fixture.logical_job_id.as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "logical-job child evidence cannot be deleted"
        );
        assert!(
            sqlx::query("TRUNCATE workflow_plan_v2_job_result_instances")
                .execute(database.pool())
                .await
                .is_err(),
            "logical-job child evidence cannot be truncated"
        );
        let short_idle_observed_at = database_now_ms(&database).await?;
        let short_idle_request = ClaimNextLogicalJobResult::new(
            LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(90_690))?,
            LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(90_691))?,
            UnixMillis::new(short_idle_observed_at),
            // The reserving transactions must finish before the later wait
            // proves expiry and bounded cleanup under hosted database load.
            UnixMillis::new(short_idle_observed_at + 5_000),
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(short_idle_request.clone())
                .await?,
            LogicalJobResultClaimNextOutcome::Idle
        ));
        wait_until_database_after(
            &database,
            first_expires_at.max(short_idle_request.expires_at().get()),
        )
        .await?;
        let cleanup_observed_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(ClaimNextLogicalJobResult::new(
                    LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(90_700))?,
                    LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(90_701))?,
                    UnixMillis::new(cleanup_observed_at),
                    UnixMillis::new(cleanup_observed_at + 5_000),
                )?)
                .await?,
            LogicalJobResultClaimNextOutcome::Idle
        ));
        let old_idle_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_job_result_selections WHERE selection_id = $1",
        )
        .bind(short_idle_request.selection_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            old_idle_count, 0,
            "expired Idle receipts are cleaned in bounded batches"
        );
        let old_claimed_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_job_result_selections WHERE selection_id = $1",
        )
        .bind(Uuid::from_u128(90_599))
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            old_claimed_count, 0,
            "expired Claimed receipts are cleaned after replay closes"
        );
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(short_idle_request)
                .await,
            Err(LogicalJobResultStoreError::SelectionExpired)
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(ClaimNextLogicalJobResult::new(
                    LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(90_702))?,
                    LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(90_703))?,
                    UnixMillis::new(cleanup_observed_at + 120_000),
                    UnixMillis::new(cleanup_observed_at + 121_000),
                )?)
                .await,
            Err(LogicalJobResultStoreError::SelectionClockSkew)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn live_selection_replay_does_not_reapply_new_reservation_clock_skew() -> TestResult {
    run_with_database(|database| async move {
        let database_now = database_now_ms(&database).await?;
        let observed_at = database_now - 59_000;
        let request = ClaimNextLogicalJobResult::new(
            LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(91_800))?,
            LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(91_801))?,
            UnixMillis::new(observed_at),
            UnixMillis::new(observed_at + 300_000),
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(request.clone())
                .await?,
            LogicalJobResultClaimNextOutcome::Idle
        ));

        assert!(
            sqlx::query(
                r"
                UPDATE workflow_plan_v2_result_selection_replay_horizons
                SET replay_floor_ms = $1, updated_at_ms = $1
                WHERE queue_name = 'job'
                ",
            )
            .bind(i64::MAX)
            .execute(database.pool())
            .await
            .is_err(),
            "an ordinary statement cannot jump the trusted replay horizon"
        );

        wait_until_database_after(&database, observed_at + 60_100).await?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(request.clone())
                .await?,
            LogicalJobResultClaimNextOutcome::Idle
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_result(ClaimNextLogicalJobResult::new(
                    LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(91_802))?,
                    request.owner(),
                    request.observed_at(),
                    request.expires_at(),
                )?)
                .await,
            Err(LogicalJobResultStoreError::SelectionClockSkew)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn zero_instance_publication_is_immediately_ready_and_skipped() -> TestResult {
    run_with_database(|database| async move {
        let fixture = fixture("logical-job-result-zero", 91_000);
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &fixture).await?;
        let activation = claim_activation(&database, &fixture, 91_100).await?;
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                activation.claim().clone(),
                false,
                Vec::new(),
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let selection_observed_at = database_now_ms(&database).await?;
        let left_request = ClaimNextLogicalJobResult::new(
            LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(91_190))?,
            LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(91_200))?,
            UnixMillis::new(selection_observed_at),
            UnixMillis::new(selection_observed_at + 3_000),
        )?;
        let right_request = ClaimNextLogicalJobResult::new(
            LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(91_191))?,
            LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(91_201))?,
            UnixMillis::new(selection_observed_at),
            UnixMillis::new(selection_observed_at + 3_000),
        );
        let (left, right) = tokio::join!(
            left_store.claim_next_logical_job_result(left_request),
            right_store.claim_next_logical_job_result(right_request?),
        );
        let claimed = match (left?, right?) {
            (
                LogicalJobResultClaimNextOutcome::Claimed(claimed),
                LogicalJobResultClaimNextOutcome::Idle,
            )
            | (
                LogicalJobResultClaimNextOutcome::Idle,
                LogicalJobResultClaimNextOutcome::Claimed(claimed),
            ) => claimed,
            outcomes => panic!("workers must claim disjoint global jobs: {outcomes:?}"),
        };
        assert_eq!(claimed.descriptor().instance_count(), 0);
        let commit = CommitLogicalJobResult::new(
            &claimed,
            &fixture.plan_bytes,
            &fixture.plan,
            UnixMillis::new(selection_observed_at + 500),
        )?;
        assert_eq!(commit.effective_conclusion(), JobConclusion::Skipped);
        assert_eq!(commit.outputs()[0].public_value(), Some(""));
        let receipt = database.store().commit_logical_job_result(commit).await?;
        assert_eq!(receipt.effective_conclusion(), JobConclusion::Skipped);
        assert!(receipt.closure_has_skipped());
        let state: String =
            sqlx::query_scalar("SELECT state FROM workflow_plan_v2_jobs WHERE id = $1")
                .bind(fixture.logical_job_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(state, "skipped");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn global_selection_quarantines_poisoned_oldest_and_continues_fairly() -> TestResult {
    run_with_database(|database| async move {
        let older = fixture("logical-job-result-fair-older", 92_000);
        let newer = fixture("logical-job-result-fair-newer", 93_000);
        let mut last_published_at = None;
        for (index, fixture) in [&older, &newer].into_iter().enumerate() {
            seed_tenant(&database, &fixture.tenant).await?;
            admit_authenticated_fixture(&database, fixture).await?;
            let activation =
                claim_activation(&database, fixture, 94_000 + u128::try_from(index)?).await?;
            if let Some(last_published_at) = last_published_at {
                wait_until_database_after(&database, last_published_at).await?;
            }
            let published_at = database_now_ms(&database).await?;
            database
                .store()
                .publish_logical_job_activation(PublishLogicalJobActivation::new(
                    activation.claim().clone(),
                    false,
                    Vec::new(),
                    UnixMillis::new(published_at),
                )?)
                .await?;
            last_published_at = Some(published_at);
        }

        poison_zero_instance_publication(&database, &older).await?;

        let selection_observed_at = database_now_ms(&database).await?;
        let first = database
            .store()
            .claim_next_logical_job_result(ClaimNextLogicalJobResult::new(
                LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(94_100))?,
                LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(94_101))?,
                UnixMillis::new(selection_observed_at),
                UnixMillis::new(selection_observed_at + 3_000),
            )?)
            .await?;
        let second = database
            .store()
            .claim_next_logical_job_result(ClaimNextLogicalJobResult::new(
                LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(94_102))?,
                LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(94_103))?,
                UnixMillis::new(selection_observed_at + 1),
                UnixMillis::new(selection_observed_at + 3_001),
            )?)
            .await?;
        assert!(matches!(
            first,
            LogicalJobResultClaimNextOutcome::Quarantined
        ));
        assert_relational_job_quarantine(&database, &older).await?;
        let LogicalJobResultClaimNextOutcome::Claimed(second) = second else {
            panic!("newer global job must remain claimable");
        };
        assert_eq!(second.claim().target().tenant().as_str(), newer.tenant);
        Ok(())
    })
    .await
}

async fn poison_zero_instance_publication(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult {
    sqlx::query(
        "ALTER TABLE workflow_plan_v2_activation_publications DISABLE TRIGGER workflow_plan_v2_activation_publications_reject_update",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        UPDATE workflow_plan_v2_activation_publications
        SET condition_matched = TRUE, instance_count = 1
        WHERE run_id = $1 AND invocation_id = $2 AND logical_job_id = $3
        ",
    )
    .bind(fixture.command.run_id().as_uuid())
    .bind(fixture.command.root_invocation_id().as_uuid())
    .bind(fixture.logical_job_id.as_uuid())
    .execute(database.pool())
    .await?;
    sqlx::query(
        "ALTER TABLE workflow_plan_v2_activation_publications ENABLE TRIGGER workflow_plan_v2_activation_publications_reject_update",
    )
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn assert_relational_job_quarantine(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult {
    let quarantine: (String, Uuid, String, bool) = sqlx::query_as(
        r"
        SELECT tenant_id, logical_job_id, failure_kind,
               claim_owner_id IS NULL
        FROM workflow_plan_v2_job_result_quarantines
        WHERE logical_job_id = $1
        ",
    )
    .bind(fixture.logical_job_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        quarantine,
        (
            fixture.tenant.clone(),
            fixture.logical_job_id.as_uuid(),
            "relational_evidence".to_owned(),
            true,
        )
    );
    let poisoned_due_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_plan_v2_job_result_due WHERE logical_job_id = $1",
    )
    .bind(fixture.logical_job_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        poisoned_due_count, 1,
        "quarantine must not launder the poisoned target"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn dependent_claim_reauthenticates_prerequisite_child_evidence() -> TestResult {
    run_with_database(|database| async move {
        let [base, prepare, build] =
            dependency_fixtures("logical-job-result-prerequisite-evidence", 95_000);
        seed_tenant(&database, &base.tenant).await?;
        admit_authenticated_fixture(&database, &base).await?;

        finalize_zero_instance_job(&database, &base, 95_100).await?;
        finalize_zero_instance_job(&database, &prepare, 95_200).await?;
        publish_zero_instance_job(&database, &build, 95_300).await?;

        assert_dependency_edge_retained(&database, &prepare, &base).await?;

        let original_commit_digest: Vec<u8> = sqlx::query_scalar(
            r"
            SELECT prerequisite_commit_digest
            FROM workflow_plan_v2_job_result_prerequisites
            WHERE logical_job_id = $1 AND prerequisite_job_id = $2
            ",
        )
        .bind(prepare.logical_job_id.as_uuid())
        .bind(base.logical_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        replace_prerequisite_commit_digest(&database, &prepare, &base, &[0xC7_u8; 32]).await?;

        let observed_at = database_now_ms(&database).await?;
        let target = LogicalJobResultTarget::new(
            TenantScope::from_authenticated_tenant_id(&build.tenant)?,
            build.command.run_id(),
            build.command.root_invocation_id(),
            build.logical_job_id,
        )?;
        assert!(matches!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    target.clone(),
                    95_400,
                    observed_at,
                    observed_at + 3_000,
                ))
                .await,
            Err(LogicalJobResultStoreError::Store(StoreError::CorruptData(
                _
            )))
        ));

        replace_prerequisite_commit_digest(&database, &prepare, &base, &original_commit_digest)
            .await?;

        let repaired_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_logical_job_result(job_result_claim(
                    target,
                    95_401,
                    repaired_at,
                    repaired_at + 3_000,
                ))
                .await?,
            LogicalJobResultClaimOutcome::Claimed(_)
        ));
        Ok(())
    })
    .await
}

async fn assert_dependency_edge_retained(
    database: &TestDatabase,
    dependent: &Fixture,
    prerequisite: &Fixture,
) -> TestResult {
    assert!(
        sqlx::query(
            r"
            DELETE FROM workflow_plan_v2_dependencies
            WHERE run_id = $1 AND invocation_id = $2
              AND logical_job_id = $3 AND prerequisite_job_id = $4
            ",
        )
        .bind(dependent.command.run_id().as_uuid())
        .bind(dependent.command.root_invocation_id().as_uuid())
        .bind(dependent.logical_job_id.as_uuid())
        .bind(prerequisite.logical_job_id.as_uuid())
        .execute(database.pool())
        .await
        .is_err(),
        "the published prerequisite edge remains retained"
    );
    Ok(())
}

async fn replace_prerequisite_commit_digest(
    database: &TestDatabase,
    dependent: &Fixture,
    prerequisite: &Fixture,
    digest: &[u8],
) -> TestResult {
    sqlx::query(
        "ALTER TABLE workflow_plan_v2_job_result_prerequisites DISABLE TRIGGER workflow_plan_v2_job_result_prerequisites_reject_update",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        UPDATE workflow_plan_v2_job_result_prerequisites
        SET prerequisite_commit_digest = $3
        WHERE logical_job_id = $1 AND prerequisite_job_id = $2
        ",
    )
    .bind(dependent.logical_job_id.as_uuid())
    .bind(prerequisite.logical_job_id.as_uuid())
    .bind(digest)
    .execute(database.pool())
    .await?;
    sqlx::query(
        "ALTER TABLE workflow_plan_v2_job_result_prerequisites ENABLE TRIGGER workflow_plan_v2_job_result_prerequisites_reject_update",
    )
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}

async fn wait_until_database_after(database: &TestDatabase, deadline_ms: i64) -> TestResult {
    sqlx::query(
        r"
        SELECT pg_sleep(GREATEST(
            0::double precision,
            ($1 - floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint + 1)
                ::double precision / 1000
        ))
        ",
    )
    .bind(deadline_ms)
    .execute(database.pool())
    .await?;
    Ok(())
}

fn fixture(tenant: &str, namespace: u128) -> Fixture {
    let tenant_scope = TenantScope::from_authenticated_tenant_id(tenant).expect("tenant");
    let manifest = fixture_manifest(tenant_scope.clone(), namespace);
    let repository_id = manifest.repository_id();
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("invocation");
    let logical_job_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("logical job");
    let plan = workflow_plan();
    let plan_bytes = serde_json::to_vec(&plan).expect("canonical plan");
    let logical_job = AdmittedLogicalWorkflowJob::new(
        logical_job_id,
        WorkflowJobKey::new("build").expect("logical key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("logical job");
    let command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!("logical-result-{namespace}"))
            .expect("idempotency"),
        Sha256Digest::from_bytes([0x40; 32]),
        AdmissionRepository::new(
            repository_id,
            "github",
            manifest.github_repository_id().get().to_string(),
            "example",
            format!("project-{namespace}"),
        )
        .expect("repository"),
        workflow_id,
        ".github/workflows/ci.yml",
        "CI",
        "refs/heads/main",
        snapshot_id,
        admission_object(
            format!("logical-result/{namespace}/source"),
            &[0x11; 512],
            "application/json",
        ),
        admission_object(
            format!("logical-result/{namespace}/plan.json"),
            &plan_bytes,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(
            format!("logical-result/{namespace}/event"),
            &[0x13; 512],
            "application/json",
        ),
        vec![0x14; 20],
        vec![logical_job],
        UnixMillis::new(1_000),
    )
    .base_context(admission_object(
        format!("logical-result/{namespace}/base-context"),
        &[0x15; 512],
        "application/vnd.automata.job-runtime-context.protobuf",
    ))
    .build()
    .expect("logical admission");
    Fixture {
        tenant: tenant.to_owned(),
        namespace,
        manifest,
        command,
        logical_job_id,
        plan,
        plan_bytes,
    }
}

#[allow(clippy::too_many_lines)]
fn dependency_fixtures(tenant: &str, namespace: u128) -> [Fixture; 3] {
    let tenant_scope = TenantScope::from_authenticated_tenant_id(tenant).expect("tenant");
    let manifest = fixture_manifest(tenant_scope.clone(), namespace);
    let repository_id = manifest.repository_id();
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("invocation");
    let base_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("base job");
    let prepare_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 7)).expect("prepare job");
    let build_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 8)).expect("build job");
    let plan = dependency_workflow_plan();
    let plan_bytes = serde_json::to_vec(&plan).expect("canonical dependency plan");
    let logical_jobs = vec![
        AdmittedLogicalWorkflowJob::new(
            base_id,
            WorkflowJobKey::new("base").expect("base key"),
            0,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        )
        .expect("base job"),
        AdmittedLogicalWorkflowJob::new(
            prepare_id,
            WorkflowJobKey::new("prepare").expect("prepare key"),
            1,
            LogicalWorkflowJobKind::Steps,
            vec![base_id],
        )
        .expect("prepare job"),
        AdmittedLogicalWorkflowJob::new(
            build_id,
            WorkflowJobKey::new("build").expect("build key"),
            2,
            LogicalWorkflowJobKind::Steps,
            vec![prepare_id],
        )
        .expect("build job"),
    ];
    let command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!(
            "logical-result-dependencies-{namespace}"
        ))
        .expect("idempotency"),
        Sha256Digest::from_bytes([0x40; 32]),
        AdmissionRepository::new(
            repository_id,
            "github",
            manifest.github_repository_id().get().to_string(),
            "example",
            format!("project-{namespace}"),
        )
        .expect("repository"),
        workflow_id,
        ".github/workflows/ci.yml",
        "CI",
        "refs/heads/main",
        snapshot_id,
        admission_object(
            format!("logical-result/{namespace}/source"),
            &[0x11; 512],
            "application/json",
        ),
        admission_object(
            format!("logical-result/{namespace}/plan.json"),
            &plan_bytes,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(
            format!("logical-result/{namespace}/event"),
            &[0x13; 512],
            "application/json",
        ),
        vec![0x14; 20],
        logical_jobs,
        UnixMillis::new(1_000),
    )
    .base_context(admission_object(
        format!("logical-result/{namespace}/base-context"),
        &[0x15; 512],
        "application/vnd.automata.job-runtime-context.protobuf",
    ))
    .build()
    .expect("dependency admission");
    [base_id, prepare_id, build_id].map(|logical_job_id| Fixture {
        tenant: tenant.to_owned(),
        namespace,
        manifest: manifest.clone(),
        command: command.clone(),
        logical_job_id,
        plan: plan.clone(),
        plan_bytes: plan_bytes.clone(),
    })
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
        GithubRepositoryName::new(format!("example/project-{namespace}")).expect("repository name"),
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(u64::try_from(namespace + 103).expect("app ID"))
            .expect("app ID"),
        GithubServerServiceAppClientId::new(format!("Iv1.logical-result-{namespace}"))
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

async fn admit_authenticated_fixture(database: &TestDatabase, fixture: &Fixture) -> TestResult {
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
                    format!("logical-job-result-{}", fixture.namespace),
                )?,
                fixture.command.request_digest(),
                fixture.command.event().clone(),
                UnixMillis::new(delivery_observed_at),
            )?,
            ProviderRepositoryOwnerId::new(
                u64::try_from(fixture.namespace + 104).expect("repository owner"),
            )?,
            ProviderRepositoryOwnerId::new(
                u64::try_from(fixture.namespace + 104).expect("repository owner"),
            )?,
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

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Logical result test', 1, 1)",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn claim_activation(
    database: &TestDatabase,
    fixture: &Fixture,
    owner: u128,
) -> TestResult<ClaimedLogicalJobActivation> {
    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
    )?;
    let preparation = match select_orchestration(database, &target, owner + 10_000).await? {
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
                format!("logical-result/{owner}/needs-context.pb"),
                &[0x52; 64],
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            UnixMillis::new(bound_at),
        )?)
        .await?;
    match select_orchestration(database, &target, owner).await? {
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
    owner: u128,
) -> TestResult<ConsumedLogicalJobOrchestrationAuthority> {
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(
                0xa200_0000_0000_0000_0000_0000_0000_0000 | owner,
            ))?,
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(owner))?,
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
    owner: u128,
) -> TestResult<ClaimedLogicalInstanceMaterialization> {
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_instance_materialization(ClaimNextLogicalInstanceMaterialization::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(
                0xb200_0000_0000_0000_0000_0000_0000_0000 | owner,
            ))?,
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(owner))?,
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

async fn publish_zero_instance_job(
    database: &TestDatabase,
    fixture: &Fixture,
    owner: u128,
) -> TestResult {
    let activation = claim_activation(database, fixture, owner).await?;
    let observed_at = database_now_ms(database).await?;
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            activation.claim().clone(),
            false,
            Vec::new(),
            UnixMillis::new(observed_at),
        )?)
        .await?;
    Ok(())
}

async fn finalize_zero_instance_job(
    database: &TestDatabase,
    fixture: &Fixture,
    owner: u128,
) -> TestResult {
    publish_zero_instance_job(database, fixture, owner).await?;
    let observed_at = database_now_ms(database).await?;
    let target = LogicalJobResultTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
    )?;
    let claimed = expect_job_result_claimed(
        database
            .store()
            .claim_logical_job_result(job_result_claim(
                target,
                owner + 50_000,
                observed_at,
                observed_at + 3_000,
            ))
            .await?,
    );
    let commit = CommitLogicalJobResult::new(
        &claimed,
        &fixture.plan_bytes,
        &fixture.plan,
        UnixMillis::new(observed_at),
    )?;
    database.store().commit_logical_job_result(commit).await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn prepared_instance(
    fixture: &Fixture,
    claimed: &ClaimedLogicalJobActivation,
    matrix_index: u32,
) -> PreparedInstance {
    let matrix_digest = Sha256Digest::from_bytes([0x70 + u8::try_from(matrix_index).unwrap(); 32]);
    let job_id = deterministic_job_id(
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
        matrix_index,
        matrix_digest,
    );
    let identity = JobInstanceIdentity::new(
        claimed.logical_key().as_str(),
        matrix_index,
        2,
        matrix_digest,
    )
    .expect("matrix identity");
    let empty = ContextValue::object(BTreeMap::new()).expect("empty context");
    let runtime_context = JobRuntimeContext::new(
        empty.clone(),
        empty.clone(),
        empty,
        StrategyContext::new(false, matrix_index, 2, 2).expect("strategy"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("runtime context");
    let runtime_encoded = serde_json::to_vec(&runtime_context).expect("runtime bytes");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes(Sha256::digest(&runtime_encoded).into()),
        ObjectKey::new(format!("logical-result/runtime-{matrix_index}.pb")).expect("runtime key"),
        u64::try_from(runtime_encoded.len()).expect("runtime size"),
    )
    .expect("runtime object");
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
    let definitions = [
        ("artifact", OutputSensitivity::Public),
        ("missing", OutputSensitivity::Public),
        ("private", OutputSensitivity::SecretDerived),
    ]
    .into_iter()
    .map(|(name, sensitivity)| {
        JobOutputDefinition::new(
            name,
            ValueTemplate::literal("value").expect("template"),
            sensitivity,
        )
        .expect("output definition")
    });
    let job = JobIr::new(
        job_id,
        fixture.command.run_id(),
        format!("Build {matrix_index}"),
        RunnerRequirements::default(),
        identity.clone(),
        false,
        vec![step],
    )
    .with_output_definitions(definitions);
    let execution = claimed.execution();
    let workspace = "/srv/work/project";
    let mut job_execution = JobExecutionContext::new(
        execution.workflow_name(),
        execution.git_ref(),
        workspace,
        admission_reference(claimed.event()),
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
            "0123456789abcdef0123456789abcdef01234567",
            ".github/workflows/ci.yml",
            "push",
        ),
        job_execution,
        job,
    );
    envelope.validate().expect("current JobIR");
    let encoded = serde_json::to_vec(&envelope).expect("encoded JobIR");
    let activated = ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        workspace.to_owned(),
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new(format!("logical-result/job-ir-{matrix_index}.pb")).expect("JobIR key"),
            u64::try_from(encoded.len()).expect("JobIR size"),
        )
        .expect("JobIR object"),
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

fn job_result(attempt_id: automata_ci_core::AttemptId, completed_at: i64) -> JobResult {
    let result = JobResult::new(
        attempt_id,
        JobConclusion::Success,
        JobSecretExposure::ReadableSecret,
        UnixMillis::new(completed_at),
    )
    .with_outputs(BTreeMap::from([
        ("artifact".to_owned(), JobResultOutput::secret_derived()),
        ("private".to_owned(), JobResultOutput::secret_derived()),
    ]));
    result.validate().expect("job result");
    result
}

async fn open_runner(
    database: &TestDatabase,
    tenant: &str,
    identity: u128,
) -> TestResult<RunnerSessionFence> {
    let runner_id = RunnerId::from_uuid(Uuid::from_u128(identity));
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    );
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots, status,
            desired_state, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,'logical-result-runner','logical-result-runner',$3::jsonb,1,'online','active',1,1)
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
            UnixMillis::new(database_now_ms(database).await?),
        ))
        .await?;
    Ok(session.fence())
}

async fn seed_terminal_result(
    database: &TestDatabase,
    session: &RunnerSessionFence,
    attempt_id: automata_ci_core::AttemptId,
    result_bytes: &[u8],
    completed_at: i64,
    operation: u128,
) -> TestResult {
    let lease_id = Uuid::from_u128(operation + 1_000);
    let mut transaction = database.pool().begin().await?;
    let activated = activate_attempt_for_terminal_result(
        &mut transaction,
        session,
        attempt_id,
        lease_id,
        completed_at,
    )
    .await?;
    if activated == 0 {
        assert_exact_terminal_replay(
            &mut transaction,
            attempt_id,
            result_bytes,
            completed_at,
            operation,
        )
        .await?;
        transaction.commit().await?;
        return Ok(());
    }
    assert_eq!(activated, 1, "the queued attempt must become active once");
    let inserted = sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, terminal_authority, runner_session_id, operation_id, runner_id,
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
    .bind(format!("logical-result/terminal-{operation}.json"))
    .bind(completed_at)
    .bind(completed_at)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    assert_eq!(inserted, 1, "terminal evidence must be inserted once");
    let due_before_lifecycle: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_plan_v2_instance_result_due WHERE attempt_id = $1",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(&mut *transaction)
    .await?;
    assert_eq!(
        due_before_lifecycle, 0,
        "an active attempt cannot become projection-ready at terminal insert"
    );
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
    .bind(completed_at)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    assert_eq!(transitioned, 1, "the active attempt must terminalize once");
    let due_after_lifecycle: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_plan_v2_instance_result_due WHERE attempt_id = $1",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(&mut *transaction)
    .await?;
    assert_eq!(
        due_after_lifecycle, 1,
        "the terminal lifecycle transition must wake projection exactly once"
    );
    transaction.commit().await?;
    Ok(())
}

async fn activate_attempt_for_terminal_result(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    session: &RunnerSessionFence,
    attempt_id: automata_ci_core::AttemptId,
    lease_id: Uuid,
    completed_at: i64,
) -> TestResult<u64> {
    Ok(sqlx::query(
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
    .execute(&mut **transaction)
    .await?
    .rows_affected())
}

async fn assert_exact_terminal_replay(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    attempt_id: automata_ci_core::AttemptId,
    result_bytes: &[u8],
    completed_at: i64,
    operation: u128,
) -> TestResult {
    let replay_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*) FROM attempt_terminal_results
        WHERE attempt_id = $1 AND operation_id = $2
          AND result_digest = $3 AND completed_at_ms = $4
          AND committed_at_ms = $5
        ",
    )
    .bind(attempt_id.as_uuid())
    .bind(Uuid::from_u128(operation))
    .bind(Sha256::digest(result_bytes).as_slice())
    .bind(completed_at)
    .bind(completed_at)
    .fetch_one(&mut **transaction)
    .await?;
    assert_eq!(replay_count, 1, "only exact terminal evidence may replay");
    Ok(())
}

async fn terminal_ordinal(
    database: &TestDatabase,
    attempt_id: automata_ci_core::AttemptId,
) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT workflow_plan_v2_terminal_ordinal FROM attempt_terminal_results WHERE attempt_id = $1",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn terminal_counter(
    database: &TestDatabase,
    logical_job_id: LogicalWorkflowJobId,
) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT last_ordinal FROM workflow_plan_v2_job_terminal_counters WHERE logical_job_id = $1",
    )
    .bind(logical_job_id.as_uuid())
    .fetch_one(database.pool())
    .await?)
}

fn job_result_claim(
    target: LogicalJobResultTarget,
    owner: u128,
    observed_at: i64,
    expires_at: i64,
) -> ClaimLogicalJobResult {
    ClaimLogicalJobResult::new(
        target,
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(owner)).expect("worker"),
        UnixMillis::new(observed_at),
        UnixMillis::new(expires_at),
    )
    .expect("logical result claim")
}

fn expect_instance_result_claimed(
    outcome: LogicalInstanceResultClaimOutcome,
) -> ClaimedLogicalInstanceResult {
    match outcome {
        LogicalInstanceResultClaimOutcome::Claimed(claimed) => claimed,
        other => panic!("expected instance-result claim, got {other:?}"),
    }
}

fn expect_job_result_claimed(outcome: LogicalJobResultClaimOutcome) -> ClaimedLogicalJobResult {
    match outcome {
        LogicalJobResultClaimOutcome::Claimed(claimed) => claimed,
        other => panic!("expected logical job-result claim, got {other:?}"),
    }
}

fn admission_object(key: String, bytes: &[u8], media: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        ObjectKey::new(key).expect("object key"),
        u64::try_from(bytes.len()).expect("object size"),
        media,
    )
    .expect("admission object")
}

fn admission_reference(object: &AdmissionObject) -> JobContentReference {
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
    matrix_digest: Sha256Digest,
) -> JobId {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.workflow-service.logical-job-id.v1\0");
    hasher.update(run_id.as_uuid().as_bytes());
    hasher.update(invocation_id.as_uuid().as_bytes());
    hasher.update(logical_job_id.as_uuid().as_bytes());
    hasher.update(matrix_index.to_be_bytes());
    hasher.update(2_u32.to_be_bytes());
    hasher.update(matrix_digest.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    JobId::from_uuid(Uuid::from_bytes(bytes))
}

fn workflow_plan() -> WorkflowPlan {
    let runner = LogicalRunnerTemplate::new(
        None,
        vec![located(CompiledValueTemplate::Literal("linux".to_owned()))],
        span(),
    );
    let step = LogicalStepTemplate::builder(
        located(WorkflowStepKey::new("position/00000000").expect("step key")),
        LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
            located(CompiledValueTemplate::Literal("true".to_owned())),
            None,
            None,
        ))),
        span(),
    )
    .build()
    .expect("step");
    let matrix = MatrixTemplate::new(
        vec![MatrixAxis::new(
            located("shard".to_owned()),
            MatrixAxisValues::Static(vec![
                located(MatrixValueTemplate::Literal(MatrixValue::Number(
                    "0".to_owned(),
                ))),
                located(MatrixValueTemplate::Literal(MatrixValue::Number(
                    "1".to_owned(),
                ))),
            ]),
            span(),
        )],
        MatrixPatchSet::Static(Vec::new()),
        MatrixPatchSet::Static(Vec::new()),
        span(),
    );
    let strategy = WorkflowStrategyTemplate::new(None, None, matrix, 8, span());
    let outputs = [
        ("artifact", OutputSensitivity::Public),
        ("missing", OutputSensitivity::Public),
        ("private", OutputSensitivity::SecretDerived),
    ]
    .into_iter()
    .map(|(name, sensitivity)| {
        LogicalJobOutputDefinition::new(
            located(WorkflowOutputKey::new(name).expect("output key")),
            LogicalJobOutputSource::Template(located(CompiledValueTemplate::Literal(
                "value".to_owned(),
            ))),
            LogicalOutputMergePolicy::LastSuccessfulCompletion,
            sensitivity,
            span(),
        )
    })
    .collect();
    let job = LogicalJobTemplate::builder(
        located(WorkflowJobKey::new("build").expect("job key")),
        0,
        LogicalJobKind::Steps(StepJobTemplate::new(runner, vec![step], span())),
        span(),
    )
    .strategy(Some(strategy))
    .outputs(outputs)
    .build()
    .expect("logical job");
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "github",
            "logical-result.yml",
            PlanSourceOrigin::Memory {
                name: "logical-result.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
        vec![job],
        span(),
    )
    .build()
    .expect("workflow plan")
}

fn dependency_workflow_plan() -> WorkflowPlan {
    let runner = LogicalRunnerTemplate::new(
        None,
        vec![located(CompiledValueTemplate::Literal("linux".to_owned()))],
        span(),
    );
    let step = LogicalStepTemplate::builder(
        located(WorkflowStepKey::new("position/00000000").expect("step key")),
        LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
            located(CompiledValueTemplate::Literal("true".to_owned())),
            None,
            None,
        ))),
        span(),
    )
    .build()
    .expect("step");
    let execution = |runner: LogicalRunnerTemplate, step: LogicalStepTemplate| {
        LogicalJobKind::Steps(StepJobTemplate::new(runner, vec![step], span()))
    };
    let base = LogicalJobTemplate::builder(
        located(WorkflowJobKey::new("base").expect("base key")),
        0,
        execution(runner.clone(), step.clone()),
        span(),
    )
    .build()
    .expect("base job");
    let prepare = LogicalJobTemplate::builder(
        located(WorkflowJobKey::new("prepare").expect("prepare key")),
        1,
        execution(runner.clone(), step.clone()),
        span(),
    )
    .needs(vec![located(
        WorkflowJobKey::new("base").expect("base need"),
    )])
    .build()
    .expect("prepare job");
    let build = LogicalJobTemplate::builder(
        located(WorkflowJobKey::new("build").expect("build key")),
        2,
        execution(runner, step),
        span(),
    )
    .needs(vec![located(
        WorkflowJobKey::new("prepare").expect("prepare need"),
    )])
    .build()
    .expect("build job");
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "github",
            "logical-result.yml",
            PlanSourceOrigin::Memory {
                name: "logical-result.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
        vec![base, prepare, build],
        span(),
    )
    .build()
    .expect("dependency workflow plan")
}

fn span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "logical-result.yml",
        PlanSourceLocation::new(0, 1, 1).expect("location"),
        PlanSourceLocation::new(1, 1, 2).expect("location"),
    )
    .expect("span")
}

fn located<T>(value: T) -> Located<T> {
    Located::new(value, span())
}
