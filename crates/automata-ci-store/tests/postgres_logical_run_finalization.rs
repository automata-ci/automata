mod common;
mod github_manifest_fixture;

use automata_ci_auth::{
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_core::{
    CompiledValueTemplate, JobAuthorityProfile, JobConclusion, Located, LogicalJobKind,
    LogicalJobTemplate, LogicalRunStepTemplate, LogicalRunnerTemplate, LogicalStepKind,
    LogicalStepTemplate, OperationId, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, RunId,
    Sha256Digest, StepJobTemplate, UnixMillis, WorkflowEventProvenance, WorkflowId, WorkflowJobKey,
    WorkflowPlan, WorkflowSourceProvenance, WorkflowStepKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AdmissionObject,
    AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation, ClaimGithubCheckProjection,
    ClaimLogicalJobResult, ClaimLogicalRunFinalization, ClaimNextLogicalJobOrchestration,
    ClaimProviderDelivery, ClaimedLogicalJobActivation, ClaimedLogicalRunFinalization,
    CommitLogicalJobResult, CommitLogicalRunFinalization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, EnsureGithubServerServiceAuthority,
    GithubCheckDesiredProjection, GithubCheckHeadSha, GithubCheckName,
    GithubCheckProjectionOutbox as _, GithubCheckProjectionWorkerId, GithubCheckTerminalCause,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE, LogicalActivationPreparationStore as _,
    LogicalActivationPreparationTarget, LogicalActivationRepository as _,
    LogicalActivationWorkerId, LogicalJobOrchestrationSelectionOutcome,
    LogicalJobResultClaimOutcome, LogicalJobResultRepository as _, LogicalJobResultTarget,
    LogicalJobResultWorkerId, LogicalRunFinalizationClaimFence, LogicalRunFinalizationDescriptor,
    LogicalRunFinalizationReceipt, LogicalRunFinalizationRepository as _,
    LogicalRunFinalizationStoreError, LogicalRunFinalizationWorkerId, LogicalRunJobResultEvidence,
    LogicalWorkSelectionId, LogicalWorkSelectionRepository as _,
    LogicalWorkflowAdmissionRepository as _, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, RerunWorkflow, RerunWorkflowByName, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowConcurrency, WorkflowRerunRepository as _,
    WorkflowRerunSelection, WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

struct Fixture {
    tenant: String,
    namespace: u128,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    job_ids: Vec<LogicalWorkflowJobId>,
    plan: WorkflowPlan,
    plan_bytes: Vec<u8>,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn zero_job_current_run_is_rejected_at_transaction_commit() -> TestResult {
    run_with_database(|database| async move {
        let fixture = fixture("run-finalization-zero", 119_000, 1);
        seed_tenant(&database, &fixture.tenant).await?;
        admit_authenticated_fixture(&database, &fixture).await?;
        let mut transaction = database.pool().begin().await?;
        let deletion = sqlx::query("DELETE FROM workflow_plan_v2_jobs WHERE id = $1")
            .bind(fixture.job_ids[0].as_uuid())
            .execute(&mut *transaction)
            .await;
        assert!(
            deletion.is_err(),
            "retained result evidence rejects removing the final logical job"
        );
        transaction.rollback().await?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM workflow_plan_v2_jobs WHERE run_id = $1")
                .bind(fixture.command.run_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(count, 1, "failed deferred validation rolls back deletion");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn linked_public_and_private_checks_terminalize_atomically_and_replay() -> TestResult {
    run_with_database(|database| async move {
        for (index, visibility) in [
            ProviderRepositoryVisibility::Public,
            ProviderRepositoryVisibility::Private,
        ]
        .into_iter()
        .enumerate()
        {
            assert_linked_check_terminalization(
                &database,
                visibility,
                125_000 + u128::try_from(index)? * 1_000,
            )
            .await?;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines, clippy::type_complexity)] // One scenario audits the full rerun tuple.
async fn terminal_rerun_replays_and_projects_one_fresh_check_to_completion() -> TestResult {
    run_with_database(|database| async move {
        let namespace = 126_000;
        let fixture = fixture("workflow-rerun-entire", namespace, 1);
        let source_subject_id = admit_authenticated_fixture(&database, &fixture).await?;
        prepare_all_jobs(&database, &fixture).await?;
        finalize_skipped_job(&database, &fixture, 0).await?;
        let claimed = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 100, 60_000).await?)
            .await?
            .ok_or("terminal rerun source was not ready for finalization")?;
        let source = database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&claimed)?)
            .await?;
        let actor = seed_rerun_actor(
            &database,
            &fixture.tenant,
            fixture.manifest.repository_id().as_uuid(),
        )
        .await?;
        let denied_repository_id = Uuid::from_u128(namespace + 190);
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'github', $3, 'denied-owner', 'denied-repository', 1, 1)
            ",
        )
        .bind(denied_repository_id)
        .bind(&fixture.tenant)
        .bind(format!("denied-{namespace}"))
        .execute(database.pool())
        .await?;
        for (owner, repository, operation) in [
            ("missing-owner", "missing-repository", namespace + 191),
            ("denied-owner", "denied-repository", namespace + 192),
        ] {
            let rejected = RerunWorkflowByName::new(
                actor.clone(),
                owner,
                repository,
                source.target().run_id(),
                WorkflowRerunSelection::EntireWorkflow,
                OperationId::from_uuid(Uuid::from_u128(operation)),
            )?;
            assert!(matches!(
                database.store().rerun_workflow_by_name(rejected).await,
                Err(automata_ci_store::WorkflowRerunStoreError::AuthorityRejected)
            ));
        }
        let unauthorized_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_admission_receipts WHERE idempotency_key IN ($1, $2)",
        )
        .bind(format!(
            "workflow-rerun:{}",
            Uuid::from_u128(namespace + 191)
        ))
        .bind(format!(
            "workflow-rerun:{}",
            Uuid::from_u128(namespace + 192)
        ))
        .fetch_one(database.pool())
        .await?;
        assert_eq!(unauthorized_receipts, 0);
        let operation_id = OperationId::from_uuid(Uuid::from_u128(namespace + 200));
        let named_request = RerunWorkflowByName::new(
            actor.clone(),
            "EXAMPLE",
            format!("PROJECT-{namespace}"),
            source.target().run_id(),
            WorkflowRerunSelection::EntireWorkflow,
            operation_id,
        )?;
        let rerun = database
            .store()
            .rerun_workflow_by_name(named_request.clone())
            .await?;
        assert_eq!(rerun.source_run_id(), source.target().run_id());
        assert_eq!(rerun.run_attempt(), 2);
        assert!(!rerun.is_replay());
        let replay = database
            .store()
            .rerun_workflow_by_name(named_request)
            .await?;
        assert!(replay.is_replay());
        assert_eq!(replay.run_id(), rerun.run_id());
        assert_eq!(replay.public_run_id(), rerun.public_run_id());
        let request = RerunWorkflow::new(
            actor,
            fixture.manifest.repository_id(),
            source.target().run_id(),
            WorkflowRerunSelection::EntireWorkflow,
            operation_id,
        )?;
        let resolved_replay = database.store().rerun_workflow(request.clone()).await?;
        assert!(resolved_replay.is_replay());
        assert_eq!(resolved_replay.run_id(), rerun.run_id());
        let audit: Vec<(Uuid, Uuid, i64, String, String, String, String, bool)> = sqlx::query_as(
            r"
                SELECT event.actor_principal_id, event.actor_session_id,
                       event.authorization_revision, event.action, event.outcome,
                       event.resource_kind, event.resource_id,
                       event.tenant_id = request.tenant_id
                       AND event.occurred_at_ms = attempt.created_at_ms
                       AND evidence.recorded_at_ms = attempt.created_at_ms
                       AND evidence.request_digest = request.request_digest
                FROM workflow_rerun_audit_evidence AS evidence
                JOIN workflow_rerun_attempts AS attempt
                  ON attempt.run_id = evidence.run_id
                JOIN workflow_rerun_requests AS request
                  ON request.tenant_id = evidence.tenant_id
                 AND request.operation_id = evidence.operation_id
                 AND request.rerun_run_id = evidence.run_id
                JOIN security_audit_events AS event
                  ON event.event_id = evidence.event_id
                WHERE evidence.run_id = $1
                ",
        )
        .bind(rerun.run_id().as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(audit.len(), 1, "replay must not duplicate its audit event");
        assert_eq!(
            audit[0].0,
            Uuid::parse_str(request.actor().principal_id().as_str())?
        );
        assert_eq!(
            audit[0].1,
            Uuid::parse_str(request.actor().session_id().as_str())?
        );
        assert_eq!(
            audit[0].2,
            i64::try_from(request.actor().authorization_revision().value())?
        );
        assert_eq!(audit[0].3, "workflow.rerun");
        assert_eq!(audit[0].4, "succeeded");
        assert_eq!(audit[0].5, "workflow_run");
        assert_eq!(audit[0].6, rerun.run_id().to_string());
        assert!(audit[0].7);

        let conflicting_request = RerunWorkflow::new(
            request.actor().clone(),
            request.repository_id(),
            request.source_run_id(),
            WorkflowRerunSelection::JobAndDependents(fixture.job_ids[0]),
            request.operation_id(),
        )?;
        assert!(matches!(
            database.store().rerun_workflow(conflicting_request).await,
            Err(automata_ci_store::WorkflowRerunStoreError::IdempotencyConflict)
        ));
        let rejected_operation = OperationId::from_uuid(Uuid::from_u128(namespace + 225));
        let rejected_request = RerunWorkflow::new(
            request.actor().clone(),
            request.repository_id(),
            request.source_run_id(),
            WorkflowRerunSelection::JobAndDependents(LogicalWorkflowJobId::from_uuid(
                Uuid::from_u128(namespace + 226),
            )?),
            rejected_operation,
        )?;
        assert!(matches!(
            database.store().rerun_workflow(rejected_request).await,
            Err(automata_ci_store::WorkflowRerunStoreError::UnsupportedSelection)
        ));
        let rolled_back: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_admission_receipts
                 WHERE idempotency_key = $1),
                (SELECT count(*) FROM workflow_rerun_requests
                 WHERE operation_id = $2)
            ",
        )
        .bind(format!("workflow-rerun:{rejected_operation}"))
        .bind(rejected_operation.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(rolled_back, (0, 0));
        let failed_selection_operation = OperationId::from_uuid(Uuid::from_u128(namespace + 227));
        let failed_selection = RerunWorkflow::new(
            request.actor().clone(),
            request.repository_id(),
            request.source_run_id(),
            WorkflowRerunSelection::FailedJobsAndDependents,
            failed_selection_operation,
        )?;
        assert!(matches!(
            database.store().rerun_workflow(failed_selection).await,
            Err(automata_ci_store::WorkflowRerunStoreError::UnsupportedSelection)
        ));
        let failed_selection_writes: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_admission_receipts
                 WHERE idempotency_key = $1),
                (SELECT count(*) FROM workflow_rerun_requests
                 WHERE operation_id = $2)
            ",
        )
        .bind(format!("workflow-rerun:{failed_selection_operation}"))
        .bind(failed_selection_operation.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(failed_selection_writes, (0, 0));

        let projected: (Uuid, Uuid, String, i64, String, i64, i64, bool, bool, bool) =
            sqlx::query_as(
                r"
            SELECT evidence.source_github_check_subject_id,
                   evidence.github_check_subject_id,
                   subject.desired_state, subject.desired_revision,
                   outbox.state, outbox.attempt_count::BIGINT,
                   outbox.projected_revision,
                   source.subject_key = subject.subject_key
                   AND source.provider_connection_id = subject.provider_connection_id
                   AND source.provider_installation_id = subject.provider_installation_id
                   AND source.github_repository_id = subject.github_repository_id
                   AND source.github_repository_name = subject.github_repository_name
                   AND source.github_app_id = subject.github_app_id
                   AND source.head_sha = subject.head_sha
                   AND source.check_name = subject.check_name,
                   authority.state = 'active'
                   AND authority.id = evidence.checks_authority_id
                   AND authority.identity_digest =
                       evidence.checks_authority_identity_digest
                   AND authority.app_configuration_revision =
                       evidence.checks_authority_app_configuration_revision
                   AND authority.policy_revision =
                       evidence.checks_authority_policy_revision,
                   run_evidence.github_check_subject_id = subject.id
                   AND run_evidence.github_check_head_sha = subject.head_sha
                   AND run_evidence.admitted_at_ms = evidence.recorded_at_ms
                   AND octet_length(run_evidence.subject_evidence_sha256) = 32
            FROM workflow_rerun_check_evidence AS evidence
            JOIN github_check_subjects AS subject
              ON subject.id = evidence.github_check_subject_id
            JOIN github_check_subjects AS source
              ON source.id = evidence.source_github_check_subject_id
            JOIN github_check_projection_outbox AS outbox
              ON outbox.subject_id = subject.id
            JOIN github_server_service_authorities AS authority
              ON authority.tenant_id = evidence.tenant_id
             AND authority.id = evidence.checks_authority_id
            JOIN github_workflow_rerun_subject_evidence AS run_evidence
              ON run_evidence.tenant_id = evidence.tenant_id
             AND run_evidence.operation_id = evidence.operation_id
             AND run_evidence.run_id = evidence.run_id
             AND run_evidence.github_check_subject_id =
                 evidence.github_check_subject_id
            WHERE evidence.run_id = $1
            ",
            )
            .bind(rerun.run_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
        assert_eq!(projected.0, source_subject_id);
        assert_ne!(projected.1, source_subject_id);
        assert_eq!(projected.2, "in_progress");
        assert_eq!(projected.3, 2);
        assert_eq!(projected.4, "pending");
        assert_eq!(projected.5, 0);
        assert_eq!(projected.6, 0);
        assert!(
            projected.7,
            "fresh Check routing must exactly match the source"
        );
        assert!(projected.8, "rerun Check must bind a live exact authority");
        assert!(
            projected.9,
            "rerun run-subject evidence must be fresh and sealed"
        );

        let immutable_error = sqlx::query(
            r"
            UPDATE github_workflow_rerun_subject_evidence
            SET admitted_at_ms = admitted_at_ms + 1
            WHERE run_id = $1
            ",
        )
        .bind(rerun.run_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("rerun run-subject evidence must be immutable");
        assert_eq!(
            immutable_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_workflow_rerun_subject_evidence_immutable"),
        );

        finalize_rerun_skipped_job(&database, &fixture, rerun.run_id(), 0).await?;
        let claimed = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 300, 60_000).await?)
            .await?
            .ok_or("rerun was not ready for finalization")?;
        assert_eq!(claimed.claim().target().run_id(), rerun.run_id());
        let commit = commit_at_claim_start(&claimed)?;
        let finalized = database
            .store()
            .commit_logical_run_finalization(commit.clone())
            .await?;
        assert_eq!(finalized.conclusion(), JobConclusion::Skipped);
        assert!(
            database
                .store()
                .commit_logical_run_finalization(commit)
                .await?
                .is_replay()
        );
        let checks: Vec<(Uuid, String, i64, Option<String>)> = sqlx::query_as(
            r"
            SELECT id, desired_state, desired_revision, desired_conclusion
            FROM github_check_subjects
            WHERE workflow_run_id IN ($1, $2)
            ORDER BY workflow_run_id, id
            ",
        )
        .bind(source.target().run_id().as_uuid())
        .bind(rerun.run_id().as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(checks.len(), 2);
        assert!(checks.iter().all(|(_, state, revision, conclusion)| {
            state == "completed" && *revision == 3 && conclusion.as_deref() == Some("skipped")
        }));
        let projection_now = database_now_ms(&database).await?;
        let first_projection = database
            .store()
            .claim_github_check_projection(ClaimGithubCheckProjection::new(
                fixture.manifest.connection_id(),
                GithubCheckProjectionWorkerId::from_uuid(Uuid::from_u128(namespace + 250))?,
                UnixMillis::new(projection_now),
                UnixMillis::new(projection_now + 60_000),
            )?)
            .await?
            .ok_or("a terminal Check projection was not claimable")?;
        let claimed_projection = if first_projection.claim().subject_id().as_uuid() == projected.1 {
            first_projection
        } else {
            assert_eq!(
                first_projection.claim().subject_id().as_uuid(),
                source_subject_id,
                "only the source Check may precede the fresh rerun Check"
            );
            database
                .store()
                .claim_github_check_projection(ClaimGithubCheckProjection::new(
                    fixture.manifest.connection_id(),
                    GithubCheckProjectionWorkerId::from_uuid(Uuid::from_u128(namespace + 251))?,
                    UnixMillis::new(projection_now),
                    UnixMillis::new(projection_now + 60_000),
                )?)
                .await?
                .ok_or("terminal rerun Check projection was not claimable")?
        };
        assert_eq!(
            claimed_projection.claim().subject_id().as_uuid(),
            projected.1
        );
        assert_eq!(
            claimed_projection.identity().rerun_run_id(),
            Some(rerun.run_id())
        );
        assert_eq!(claimed_projection.identity().delivery_id(), None);
        assert_eq!(claimed_projection.identity().schedule_fire_id(), None);
        assert_eq!(claimed_projection.desired_revision(), 3);
        assert_eq!(
            claimed_projection.desired(),
            GithubCheckDesiredProjection::Terminal(GithubCheckTerminalCause::WorkflowSkipped)
        );
        let durable_counts: (i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_rerun_requests WHERE rerun_run_id = $1),
                (SELECT count(*) FROM workflow_rerun_check_evidence WHERE run_id = $1),
                (SELECT count(*) FROM github_workflow_rerun_subject_evidence
                 WHERE run_id = $1),
                (SELECT count(*) FROM github_check_projection_outbox AS outbox
                 JOIN workflow_rerun_check_evidence AS evidence
                   ON evidence.github_check_subject_id = outbox.subject_id
                 WHERE evidence.run_id = $1)
            ",
        )
        .bind(rerun.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable_counts, (1, 1, 1, 1));

        let concurrent_left = RerunWorkflow::new(
            request.actor().clone(),
            request.repository_id(),
            rerun.run_id(),
            WorkflowRerunSelection::EntireWorkflow,
            OperationId::from_uuid(Uuid::from_u128(namespace + 600)),
        )?;
        let concurrent_right = RerunWorkflow::new(
            request.actor().clone(),
            request.repository_id(),
            rerun.run_id(),
            WorkflowRerunSelection::EntireWorkflow,
            OperationId::from_uuid(Uuid::from_u128(namespace + 601)),
        )?;
        let (left, right) = tokio::join!(
            database.store().rerun_workflow(concurrent_left),
            database.store().rerun_workflow(concurrent_right),
        );
        let mut attempts = [left?.run_attempt(), right?.run_attempt()];
        attempts.sort_unstable();
        assert_eq!(attempts, [3, 4]);
        let concurrent_shape: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT count(*)::BIGINT,
                   count(DISTINCT attempt.run_id)::BIGINT,
                   count(DISTINCT attempt.attempt)::BIGINT,
                   (SELECT count(*) FROM workflow_rerun_requests
                    WHERE repository_id = $2),
                   (SELECT count(*) FROM workflow_rerun_check_evidence
                    WHERE repository_id = $2)
            FROM workflow_rerun_attempts AS attempt
            WHERE attempt.root_run_id = $1
            ",
        )
        .bind(source.target().run_id().as_uuid())
        .bind(request.repository_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(concurrent_shape, (4, 4, 4, 3, 3));

        let authority_now = database_now_ms(&database).await?;
        let retired = sqlx::query(
            r"
            UPDATE github_server_service_authorities
            SET state = 'retiring', current_issuance_generation = NULL,
                refresh_issuance_generation = NULL, state_updated_at_ms = $2
            WHERE id = $1 AND state = 'active'
            ",
        )
        .bind(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT checks_authority_id FROM workflow_rerun_check_evidence WHERE run_id = $1",
            )
            .bind(rerun.run_id().as_uuid())
            .fetch_one(database.pool())
            .await?,
        )
        .bind(authority_now)
        .execute(database.pool())
        .await?;
        assert_eq!(retired.rows_affected(), 1);
        let stale_authority_operation = OperationId::from_uuid(Uuid::from_u128(namespace + 700));
        assert!(matches!(
            database
                .store()
                .rerun_workflow(RerunWorkflow::new(
                    request.actor().clone(),
                    request.repository_id(),
                    rerun.run_id(),
                    WorkflowRerunSelection::EntireWorkflow,
                    stale_authority_operation,
                )?)
                .await,
            Err(automata_ci_store::WorkflowRerunStoreError::UnsupportedSelection)
        ));
        let stale_authority_writes: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_admission_receipts
                 WHERE idempotency_key = $1),
                (SELECT count(*) FROM workflow_rerun_requests
                 WHERE operation_id = $2)
            ",
        )
        .bind(format!("workflow-rerun:{stale_authority_operation}"))
        .bind(stale_authority_operation.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(stale_authority_writes, (0, 0));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // Closed rerun failures share exact no-write assertions.
async fn workflow_rerun_closed_errors_are_atomic_and_database_timed() -> TestResult {
    run_with_database(|database| async move {
        let namespace = 126_300;
        let fixture = fixture("workflow-rerun-closed-errors", namespace, 1);
        admit_authenticated_fixture(&database, &fixture).await?;
        let actor = seed_rerun_actor(
            &database,
            &fixture.tenant,
            fixture.manifest.repository_id().as_uuid(),
        )
        .await?;

        let missing_operation = OperationId::from_uuid(Uuid::from_u128(namespace + 100));
        assert!(matches!(
            database
                .store()
                .rerun_workflow(RerunWorkflow::new(
                    actor.clone(),
                    fixture.manifest.repository_id(),
                    RunId::from_uuid(Uuid::from_u128(namespace + 101)),
                    WorkflowRerunSelection::EntireWorkflow,
                    missing_operation,
                )?)
                .await,
            Err(automata_ci_store::WorkflowRerunStoreError::NotFound)
        ));
        assert_rerun_operation_has_no_writes(&database, missing_operation).await?;

        let live_operation = OperationId::from_uuid(Uuid::from_u128(namespace + 110));
        assert!(matches!(
            database
                .store()
                .rerun_workflow(RerunWorkflow::new(
                    actor.clone(),
                    fixture.manifest.repository_id(),
                    fixture.command.run_id(),
                    WorkflowRerunSelection::EntireWorkflow,
                    live_operation,
                )?)
                .await,
            Err(automata_ci_store::WorkflowRerunStoreError::SourceNotTerminal)
        ));
        assert_rerun_operation_has_no_writes(&database, live_operation).await?;

        prepare_all_jobs(&database, &fixture).await?;
        finalize_skipped_job(&database, &fixture, 0).await?;
        let source_claim = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 120, 60_000).await?)
            .await?
            .ok_or("closed-error source was not ready")?;
        database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&source_claim)?)
            .await?;

        let now = database_now_ms(&database).await?;
        for (offset, label) in [
            (
                -(automata_ci_store::MAX_WORKFLOW_RERUN_AGE_MILLIS + 1),
                "expired",
            ),
            (60_000, "future"),
        ] {
            sqlx::query(
                "ALTER TABLE workflow_runs DISABLE TRIGGER workflow_runs_enforce_plan_v2_immutable",
            )
            .execute(database.pool())
            .await?;
            sqlx::query("UPDATE workflow_runs SET created_at_ms = $2 WHERE repository_id = $1")
                .bind(fixture.manifest.repository_id().as_uuid())
                .bind(now.saturating_add(offset))
                .execute(database.pool())
                .await?;
            sqlx::query(
                "ALTER TABLE workflow_runs ENABLE TRIGGER workflow_runs_enforce_plan_v2_immutable",
            )
            .execute(database.pool())
            .await?;
            let operation = OperationId::new();
            let result = database
                .store()
                .rerun_workflow(RerunWorkflow::new(
                    actor.clone(),
                    fixture.manifest.repository_id(),
                    fixture.command.run_id(),
                    WorkflowRerunSelection::EntireWorkflow,
                    operation,
                )?)
                .await;
            assert!(
                matches!(
                    result,
                    Err(automata_ci_store::WorkflowRerunStoreError::SourceExpired)
                ),
                "{label} source must be closed"
            );
            assert_rerun_operation_has_no_writes(&database, operation).await?;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // Unsupported authority, concurrency, and context share no-write proof.
async fn private_rerun_authority_is_live_and_grouped_sources_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let namespace = 126_400;
        let private = fixture_with_visibility(
            "workflow-rerun-private",
            namespace,
            1,
            ProviderRepositoryVisibility::Private,
            false,
        );
        admit_and_finalize_all_skipped(&database, &private).await?;
        let source_claim = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 100, 60_000).await?)
            .await?
            .ok_or("private source was not ready")?;
        let source = database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&source_claim)?)
            .await?;
        let actor = seed_rerun_actor(
            &database,
            &private.tenant,
            private.manifest.repository_id().as_uuid(),
        )
        .await?;
        let rerun = database
            .store()
            .rerun_workflow(RerunWorkflow::new(
                actor.clone(),
                private.manifest.repository_id(),
                source.target().run_id(),
                WorkflowRerunSelection::EntireWorkflow,
                OperationId::from_uuid(Uuid::from_u128(namespace + 200)),
            )?)
            .await?;
        let private_evidence: bool = sqlx::query_scalar(
            r"
            SELECT evidence.private_source_authority_id =
                       origin.private_source_authority_id
                   AND evidence.private_source_authority_identity_digest =
                       origin.private_source_authority_identity_digest
            FROM workflow_rerun_check_evidence AS evidence
            JOIN workflow_rerun_attempts AS attempt
              ON attempt.run_id = evidence.run_id
            JOIN github_workflow_run_base_manifest_origins AS origin
              ON origin.run_id = attempt.root_run_id
            WHERE evidence.run_id = $1
            ",
        )
        .bind(rerun.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(private_evidence);
        finalize_rerun_skipped_job(&database, &private, rerun.run_id(), 0).await?;
        let rerun_claim = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 300, 60_000).await?)
            .await?
            .ok_or("private rerun was not ready")?;
        database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&rerun_claim)?)
            .await?;

        let now = database_now_ms(&database).await?;
        let retired = sqlx::query(
            r"
            UPDATE github_server_service_authorities
            SET state = 'retiring', current_issuance_generation = NULL,
                refresh_issuance_generation = NULL, state_updated_at_ms = $2
            WHERE id = (
                SELECT private_source_authority_id
                FROM github_workflow_run_base_manifest_origins
                WHERE run_id = $1
            )
              AND state = 'active'
            ",
        )
        .bind(source.target().run_id().as_uuid())
        .bind(now)
        .execute(database.pool())
        .await?;
        assert_eq!(retired.rows_affected(), 1);
        let retired_operation = OperationId::from_uuid(Uuid::from_u128(namespace + 400));
        assert!(matches!(
            database
                .store()
                .rerun_workflow(RerunWorkflow::new(
                    actor,
                    private.manifest.repository_id(),
                    rerun.run_id(),
                    WorkflowRerunSelection::EntireWorkflow,
                    retired_operation,
                )?)
                .await,
            Err(automata_ci_store::WorkflowRerunStoreError::UnsupportedSelection)
        ));
        assert_rerun_operation_has_no_writes(&database, retired_operation).await?;

        let grouped = fixture_with_concurrency(
            "workflow-rerun-grouped-unsupported",
            namespace + 500,
            1,
            true,
        );
        admit_and_finalize_all_skipped(&database, &grouped).await?;
        let grouped_claim = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 700, 60_000).await?)
            .await?
            .ok_or("grouped source was not ready")?;
        let grouped_source = database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&grouped_claim)?)
            .await?;
        let grouped_actor = seed_rerun_actor(
            &database,
            &grouped.tenant,
            grouped.manifest.repository_id().as_uuid(),
        )
        .await?;
        let grouped_operation = OperationId::from_uuid(Uuid::from_u128(namespace + 800));
        assert!(matches!(
            database
                .store()
                .rerun_workflow(RerunWorkflow::new(
                    grouped_actor,
                    grouped.manifest.repository_id(),
                    grouped_source.target().run_id(),
                    WorkflowRerunSelection::EntireWorkflow,
                    grouped_operation,
                )?)
                .await,
            Err(automata_ci_store::WorkflowRerunStoreError::UnsupportedSelection)
        ));
        assert_rerun_operation_has_no_writes(&database, grouped_operation).await?;

        let legacy = fixture("workflow-rerun-legacy-context", namespace + 900, 1);
        admit_and_finalize_all_skipped(&database, &legacy).await?;
        let legacy_claim = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 1_100, 60_000).await?)
            .await?
            .ok_or("legacy-context source was not ready")?;
        let legacy_source = database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&legacy_claim)?)
            .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_runs DISABLE TRIGGER workflow_plan_v2_runs_base_context_immutable",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE workflow_plan_v2_runs
            SET base_context_digest = NULL,
                base_context_object_key = NULL,
                base_context_size_bytes = NULL,
                base_context_media_type = NULL,
                base_context_schema = NULL
            WHERE run_id = $1
            ",
        )
        .bind(legacy_source.target().run_id().as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_runs ENABLE TRIGGER workflow_plan_v2_runs_base_context_immutable",
        )
        .execute(database.pool())
        .await?;
        let legacy_actor = seed_rerun_actor(
            &database,
            &legacy.tenant,
            legacy.manifest.repository_id().as_uuid(),
        )
        .await?;
        let legacy_operation = OperationId::from_uuid(Uuid::from_u128(namespace + 1_200));
        assert!(matches!(
            database
                .store()
                .rerun_workflow(RerunWorkflow::new(
                    legacy_actor,
                    legacy.manifest.repository_id(),
                    legacy_source.target().run_id(),
                    WorkflowRerunSelection::EntireWorkflow,
                    legacy_operation,
                )?)
                .await,
            Err(automata_ci_store::WorkflowRerunStoreError::UnsupportedSelection)
        ));
        assert_rerun_operation_has_no_writes(&database, legacy_operation).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // Nested selection and effective carry evidence stay together.
async fn partial_rerun_carries_prerequisites_through_a_nested_rerun() -> TestResult {
    run_with_database(|database| async move {
        let namespace = 126_500;
        let fixture = fixture_with_visibility_and_dependencies(
            "workflow-rerun-nested",
            namespace,
            3,
            ProviderRepositoryVisibility::Public,
            false,
            true,
        );
        admit_authenticated_fixture(&database, &fixture).await?;
        for index in 0..3 {
            finalize_skipped_job(&database, &fixture, index).await?;
        }
        let source_claim = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 100, 60_000).await?)
            .await?
            .ok_or("source chain was not ready")?;
        let source = database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&source_claim)?)
            .await?;
        let actor = seed_rerun_actor(
            &database,
            &fixture.tenant,
            fixture.manifest.repository_id().as_uuid(),
        )
        .await?;
        let first = database
            .store()
            .rerun_workflow(RerunWorkflow::new(
                actor.clone(),
                fixture.manifest.repository_id(),
                source.target().run_id(),
                WorkflowRerunSelection::JobAndDependents(fixture.job_ids[1]),
                OperationId::from_uuid(Uuid::from_u128(namespace + 200)),
            )?)
            .await?;
        let first_shape: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT count(*)::BIGINT,
                   count(*) FILTER (WHERE mapping.selected)::BIGINT,
                   count(*) FILTER (WHERE NOT mapping.selected)::BIGINT
            FROM workflow_rerun_attempt_jobs AS mapping
            WHERE mapping.run_id = $1
            ",
        )
        .bind(first.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(first_shape, (3, 2, 1));
        finalize_rerun_skipped_job(&database, &fixture, first.run_id(), 1).await?;
        finalize_rerun_skipped_job(&database, &fixture, first.run_id(), 2).await?;
        let first_claim = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 300, 60_000).await?)
            .await?
            .ok_or("first partial rerun was not ready")?;
        database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&first_claim)?)
            .await?;

        let nested_source_job = LogicalWorkflowJobId::from_uuid(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM workflow_plan_v2_jobs WHERE run_id = $1 AND source_order = 2",
            )
            .bind(first.run_id().as_uuid())
            .fetch_one(database.pool())
            .await?,
        )?;
        let nested = database
            .store()
            .rerun_workflow(RerunWorkflow::new(
                actor,
                fixture.manifest.repository_id(),
                first.run_id(),
                WorkflowRerunSelection::JobAndDependents(nested_source_job),
                OperationId::from_uuid(Uuid::from_u128(namespace + 400)),
            )?)
            .await?;
        assert_eq!(nested.run_attempt(), 3);
        let nested_shape: (i64, i64, i64, i64, bool) = sqlx::query_as(
            r"
            SELECT count(*)::BIGINT,
                   count(*) FILTER (WHERE mapping.selected)::BIGINT,
                   count(*) FILTER (WHERE NOT mapping.selected)::BIGINT,
                   (SELECT count(*)::BIGINT
                    FROM workflow_rerun_carried_job_results
                    WHERE run_id = $1),
                   bool_and(
                       mapping.selected
                       OR effective.carried
                       AND effective.claim_state = 'finalized'
                   )
            FROM workflow_rerun_attempt_jobs AS mapping
            LEFT JOIN workflow_plan_v2_effective_job_results AS effective
              ON effective.run_id = mapping.run_id
             AND effective.logical_job_id = mapping.logical_job_id
            WHERE mapping.run_id = $1
            ",
        )
        .bind(nested.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(nested_shape, (3, 1, 2, 2, true));
        assert_late_rerun_carry_mutations_are_rejected(&database, nested.run_id()).await?;
        let check_chain_exact: bool = sqlx::query_scalar(
            r"
            SELECT evidence.source_github_check_subject_id = source_subject.id
            FROM workflow_rerun_check_evidence AS evidence
            JOIN github_check_subjects AS source_subject
              ON source_subject.workflow_run_id = $2
            WHERE evidence.run_id = $1
            ",
        )
        .bind(nested.run_id().as_uuid())
        .bind(first.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(check_chain_exact);

        finalize_rerun_skipped_job(&database, &fixture, nested.run_id(), 2).await?;
        let nested_claim = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 500, 60_000).await?)
            .await?
            .ok_or("nested partial rerun was not ready")?;
        database
            .store()
            .commit_logical_run_finalization(commit_at_claim_start(&nested_claim)?)
            .await?;
        let terminal_checks: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)::BIGINT
            FROM github_check_subjects
            WHERE workflow_run_id IN ($1, $2, $3)
              AND desired_state = 'completed'
              AND desired_revision = 3
            ",
        )
        .bind(source.target().run_id().as_uuid())
        .bind(first.run_id().as_uuid())
        .bind(nested.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(terminal_checks, 3);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn mismatched_linked_check_rolls_back_the_entire_finalization() -> TestResult {
    run_with_database(|database| async move {
        let namespace = 127_000;
        let fixture = fixture("run-finalization-check-mismatch", namespace, 1);
        let subject_id = admit_authenticated_fixture(&database, &fixture).await?;
        set_linked_check_back_to_queued(&database, subject_id).await?;
        finalize_skipped_job(&database, &fixture, 0).await?;
        let claimed = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, namespace + 100, 60_000).await?)
            .await?
            .ok_or("mismatched linked run was not ready for finalization")?;
        let commit = commit_at_claim_start(&claimed)?;

        assert!(matches!(
            database
                .store()
                .commit_logical_run_finalization(commit.clone())
                .await,
            Err(LogicalRunFinalizationStoreError::Store(_))
        ));
        let unchanged: (i64, String, String, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_plan_v2_run_results WHERE run_id = $1),
                run.status, subject.desired_state, subject.desired_revision
            FROM workflow_runs AS run
            JOIN github_check_subjects AS subject
              ON subject.workflow_run_id = run.id
            WHERE run.id = $1 AND subject.id = $2
            ",
        )
        .bind(fixture.command.run_id().as_uuid())
        .bind(subject_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(unchanged, (0, "queued".into(), "queued".into(), 1));

        sqlx::query(
            r"
            UPDATE github_check_subjects
            SET desired_state = 'in_progress', desired_revision = 2,
                desired_updated_at_ms = linked_at_ms
            WHERE id = $1
            ",
        )
        .bind(subject_id)
        .execute(database.pool())
        .await?;
        assert_eq!(
            database
                .store()
                .commit_logical_run_finalization(commit)
                .await?
                .conclusion(),
            JobConclusion::Skipped
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn parallel_claims_takeover_replay_and_atomic_terminal_state() -> TestResult {
    run_with_database(|database| async move {
        let (first, second) = claim_two_ready_runs(&database).await?;
        assert_claimed_graph_and_evidence_are_immutable(&database, &first).await?;
        assert_takeover_replay_and_atomic_terminal_state(&database, &first, &second).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn incomplete_run_is_excluded_and_sql_precedence_matches_domain() -> TestResult {
    run_with_database(|database| async move {
        let fixture = fixture("run-finalization-precedence", 123_000, 3);
        admit_authenticated_fixture(&database, &fixture).await?;
        prepare_all_jobs(&database, &fixture).await?;
        finalize_skipped_job(&database, &fixture, 0).await?;
        assert!(
            database
                .store()
                .claim_logical_run_finalization(run_claim(&database, 123_100, 60_000).await?)
                .await?
                .is_none(),
            "one finalized job cannot close a three-job root invocation"
        );
        finalize_skipped_job(&database, &fixture, 1).await?;
        finalize_skipped_job(&database, &fixture, 2).await?;

        // This test fixture changes already trusted 0025 rows only to exercise
        // the run-level SQL precedence and transition mapping. The immutable
        // rejection trigger is disabled for the narrow update and restored
        // before 0031 observes or claims any evidence.
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_results DISABLE TRIGGER workflow_plan_v2_job_results_reject_update",
        )
        .execute(database.pool())
        .await?;
        for (index, (conclusion, failure, cancelled, skipped, state)) in [
            ("failure", true, false, false, "failed"),
            ("timed_out", true, false, false, "failed"),
            ("cancelled", false, true, false, "cancelled"),
        ]
        .into_iter()
        .enumerate()
        {
            sqlx::query(
                r"
                UPDATE workflow_plan_v2_job_results
                SET effective_conclusion = $2, closure_has_failure = $3,
                    closure_has_cancelled = $4, closure_has_skipped = $5,
                    commit_digest = $6
                WHERE logical_job_id = $1
                ",
            )
            .bind(fixture.job_ids[index].as_uuid())
            .bind(conclusion)
            .bind(failure)
            .bind(cancelled)
            .bind(skipped)
            .bind(vec![0x90 + u8::try_from(index)?; 32])
            .execute(database.pool())
            .await?;
            sqlx::query(
                "UPDATE workflow_plan_v2_jobs SET state = $2 WHERE id = $1",
            )
            .bind(fixture.job_ids[index].as_uuid())
            .bind(state)
            .execute(database.pool())
            .await?;
        }
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_job_results ENABLE TRIGGER workflow_plan_v2_job_results_reject_update",
        )
        .execute(database.pool())
        .await?;

        let claimed = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, 123_101, 60_000).await?)
            .await?
            .ok_or("complete precedence fixture was not claimed")?;
        let commit = commit_at_claim_start(&claimed)?;
        assert_eq!(commit.conclusion(), JobConclusion::Failure);
        let receipt = database
            .store()
            .commit_logical_run_finalization(commit)
            .await?;
        assert_eq!(receipt.conclusion(), JobConclusion::Failure);
        let states: (String, String, String) = sqlx::query_as(
            r"
            SELECT invocation.state, marker.state, run.status
            FROM workflow_plan_v2_runs AS marker
            JOIN workflow_plan_v2_invocations AS invocation
              ON invocation.run_id = marker.run_id
             AND invocation.id = marker.root_invocation_id
            JOIN workflow_runs AS run ON run.id = marker.run_id
            WHERE marker.run_id = $1
            ",
        )
        .bind(receipt.target().run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(states, ("failed".into(), "failed".into(), "completed".into()));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn preterminal_concurrency_cancellation_closes_with_immutable_run_evidence() -> TestResult {
    run_with_database(|database| async move {
        let fixture =
            fixture_with_concurrency("run-finalization-preterminal-cancel", 124_000, 1, true);
        admit_and_finalize_all_skipped(&database, &fixture).await?;
        record_concurrency_cancellation(&database, &fixture).await?;

        let claimed = database
            .store()
            .claim_logical_run_finalization(run_claim(&database, 124_100, 60_000).await?)
            .await?
            .ok_or("pre-terminal cancelled run was not claimed")?;
        assert_eq!(
            claimed.descriptor().workflow_status(),
            automata_ci_store::LogicalRunFinalizationWorkflowStatus::Cancelled
        );
        let commit = commit_at_claim_start(&claimed)?;
        assert_eq!(commit.conclusion(), JobConclusion::Cancelled);
        let receipt = database
            .store()
            .commit_logical_run_finalization(commit.clone())
            .await?;
        assert_eq!(receipt.conclusion(), JobConclusion::Cancelled);
        assert!(
            database
                .store()
                .commit_logical_run_finalization(commit)
                .await?
                .is_replay()
        );

        let states: (String, String, String, String, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT invocation.state, marker.state, run.status,
                   result.effective_conclusion, invocation.updated_at_ms,
                   marker.updated_at_ms, run.updated_at_ms
            FROM workflow_plan_v2_run_results AS result
            JOIN workflow_plan_v2_runs AS marker ON marker.run_id = result.run_id
            JOIN workflow_plan_v2_invocations AS invocation
              ON invocation.run_id = result.run_id
             AND invocation.id = result.root_invocation_id
            JOIN workflow_runs AS run ON run.id = result.run_id
            WHERE result.run_id = $1
            ",
        )
        .bind(receipt.target().run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            states,
            (
                "cancelled".into(),
                "cancelled".into(),
                "cancelled".into(),
                "cancelled".into(),
                receipt.finalized_at().get(),
                receipt.finalized_at().get(),
                receipt.finalized_at().get(),
            )
        );
        assert!(
            sqlx::query("UPDATE workflow_runs SET updated_at_ms = 1500 WHERE id = $1")
                .bind(receipt.target().run_id().as_uuid())
                .execute(database.pool())
                .await
                .is_err(),
            "a finalized cancellation timestamp must be immutable"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn database_time_issues_claims_and_decides_takeover_and_commit_liveness() -> TestResult {
    run_with_database(|database| async move {
        assert_database_time_claim_and_takeover(&database).await?;
        assert_database_time_commit_fence(&database).await?;
        assert_database_time_expired_fresh_commit(&database).await?;
        Ok(())
    })
    .await
}

async fn assert_database_time_claim_and_takeover(database: &TestDatabase) -> TestResult {
    let fixture = fixture("run-finalization-database-time", 128_000, 1);
    admit_and_finalize_all_skipped(database, &fixture).await?;
    assert_clock_skew_is_side_effect_free(database, &fixture).await?;

    let before_claim = database_now_ms(database).await?;
    let first = database
        .store()
        .claim_logical_run_finalization(explicit_run_claim(128_102, before_claim, 2_000)?)
        .await?
        .ok_or("database-time fixture was not claimed")?;
    let after_claim = database_now_ms(database).await?;
    assert!(
        (before_claim..=after_claim).contains(&first.claim().claimed_at().get()),
        "the repository issues claim start from database time"
    );
    assert_eq!(
        first.claim().expires_at().get() - first.claim().claimed_at().get(),
        2_000,
        "only the bounded requested duration survives"
    );

    let fast_but_bounded = database_now_ms(database).await? + 30_000;
    assert!(
        database
            .store()
            .claim_logical_run_finalization(explicit_run_claim(128_103, fast_but_bounded, 5_000,)?)
            .await?
            .is_none(),
        "a fast caller cannot supersede a database-live claim"
    );

    wait_until_database_time(database, first.claim().expires_at().get()).await?;
    let takeover_database_now = database_now_ms(database).await?;
    let slow_observed_at = takeover_database_now - 30_000;
    let slow_request = explicit_run_claim(128_104, slow_observed_at, 5_000)?;
    assert!(
        slow_request.expires_at().get() < takeover_database_now,
        "the caller's absolute expiration is deliberately stale"
    );
    let takeover = database
        .store()
        .claim_logical_run_finalization(slow_request)
        .await?
        .ok_or("a slow caller deferred a database-expired claim")?;
    assert_eq!(takeover.claim().generation().get(), 2);
    assert!(takeover.claim().claimed_at().get() >= takeover_database_now);
    assert_eq!(
        takeover.claim().expires_at().get() - takeover.claim().claimed_at().get(),
        5_000
    );
    database
        .store()
        .commit_logical_run_finalization(commit_at_claim_start(&takeover)?)
        .await?;
    Ok(())
}

async fn assert_clock_skew_is_side_effect_free(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult {
    let database_now = database_now_ms(database).await?;
    for (owner, observed_at) in [
        (128_100, database_now - 120_000),
        (128_101, database_now + 120_000),
    ] {
        let rejected = explicit_run_claim(owner, observed_at, 5_000)?;
        assert!(matches!(
            database
                .store()
                .claim_logical_run_finalization(rejected)
                .await,
            Err(LogicalRunFinalizationStoreError::ClaimRejected)
        ));
    }
    let claim_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_plan_v2_run_result_claims WHERE run_id = $1",
    )
    .bind(fixture.command.run_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(claim_count, 0, "clock-skew rejection is side-effect free");
    Ok(())
}

async fn assert_database_time_commit_fence(database: &TestDatabase) -> TestResult {
    let fixture = fixture("run-finalization-database-commit", 129_000, 1);
    admit_and_finalize_all_skipped(database, &fixture).await?;
    let claimed = database
        .store()
        .claim_logical_run_finalization(run_claim(database, 129_100, 5_000).await?)
        .await?
        .ok_or("database-time commit fixture was not claimed")?;
    let fast_commit = CommitLogicalRunFinalization::new(
        &claimed,
        UnixMillis::new(claimed.claim().claimed_at().get() + 2_500),
    )?;
    assert!(matches!(
        database
            .store()
            .commit_logical_run_finalization(fast_commit)
            .await,
        Err(LogicalRunFinalizationStoreError::ClaimRejected)
    ));
    let result_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflow_plan_v2_run_results WHERE run_id = $1")
            .bind(fixture.command.run_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(
        result_count, 0,
        "caller time cannot bypass the commit fence"
    );
    let commit = commit_at_claim_start(&claimed)?;
    let receipt = database
        .store()
        .commit_logical_run_finalization(commit.clone())
        .await?;
    wait_until_database_time(database, claimed.claim().expires_at().get()).await?;
    let replay = database
        .store()
        .commit_logical_run_finalization(commit.clone())
        .await?;
    assert_eq!(replay, LogicalRunFinalizationReceipt::new(&commit, true));
    assert_eq!(replay.commit_digest(), receipt.commit_digest());
    Ok(())
}

async fn assert_database_time_expired_fresh_commit(database: &TestDatabase) -> TestResult {
    let fixture = fixture("run-finalization-database-expired-commit", 129_500, 1);
    admit_and_finalize_all_skipped(database, &fixture).await?;
    let claimed = database
        .store()
        .claim_logical_run_finalization(run_claim(database, 129_600, 250).await?)
        .await?
        .ok_or("database-time expired-commit fixture was not claimed")?;
    let commit = commit_at_claim_start(&claimed)?;
    wait_until_database_time(database, claimed.claim().expires_at().get()).await?;
    assert!(matches!(
        database
            .store()
            .commit_logical_run_finalization(commit)
            .await,
        Err(LogicalRunFinalizationStoreError::ClaimRejected)
    ));
    let result_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflow_plan_v2_run_results WHERE run_id = $1")
            .bind(fixture.command.run_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(
        result_count, 0,
        "an expired fresh commit is side-effect free"
    );
    Ok(())
}

async fn assert_linked_check_terminalization(
    database: &TestDatabase,
    visibility: ProviderRepositoryVisibility,
    namespace: u128,
) -> TestResult {
    let visibility_name = match visibility {
        ProviderRepositoryVisibility::Public => "public",
        ProviderRepositoryVisibility::Private => "private",
    };
    let fixture = fixture_with_visibility(
        &format!("run-finalization-check-{visibility_name}"),
        namespace,
        1,
        visibility,
        false,
    );
    let subject_id = admit_authenticated_fixture(database, &fixture).await?;
    finalize_skipped_job(database, &fixture, 0).await?;

    let claimed = database
        .store()
        .claim_logical_run_finalization(run_claim(database, namespace + 100, 60_000).await?)
        .await?
        .ok_or("linked GitHub run was not ready for finalization")?;
    let commit = commit_at_claim_start(&claimed)?;
    let receipt = database
        .store()
        .commit_logical_run_finalization(commit.clone())
        .await?;
    assert_eq!(receipt.conclusion(), JobConclusion::Skipped);
    assert!(!receipt.is_replay());
    assert!(
        database
            .store()
            .commit_logical_run_finalization(commit.clone())
            .await?
            .is_replay()
    );

    let state: (
        String,
        Option<String>,
        Option<String>,
        i64,
        i64,
        String,
        i64,
    ) = sqlx::query_as(
        r"
            SELECT subject.desired_state, subject.desired_conclusion,
                   subject.terminal_cause, subject.desired_revision,
                   subject.desired_updated_at_ms, outbox.state,
                   outbox.state_updated_at_ms
            FROM github_check_subjects AS subject
            JOIN github_check_projection_outbox AS outbox
              ON outbox.subject_id = subject.id
            WHERE subject.id = $1
            ",
    )
    .bind(subject_id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        state,
        (
            "completed".into(),
            Some("skipped".into()),
            Some("workflow_skipped".into()),
            3,
            receipt.finalized_at().get(),
            "pending".into(),
            receipt.finalized_at().get(),
        )
    );

    seed_additional_linked_github_check(database, &fixture, subject_id, namespace + 500).await?;
    assert!(matches!(
        database
            .store()
            .commit_logical_run_finalization(commit)
            .await,
        Err(LogicalRunFinalizationStoreError::CommitConflict)
    ));
    Ok(())
}

async fn admit_authenticated_fixture(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult<Uuid> {
    let configured_at = database_now_ms(database).await?;
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                fixture.manifest.clone(),
                UnixMillis::new(configured_at),
            ),
        )
        .await?;
    ensure_fixture_authority(
        database,
        fixture,
        GithubServerServiceScope::ChecksWrite,
        800,
        0x71,
        configured_at,
    )
    .await?;
    if fixture.manifest.repository_visibility() == ProviderRepositoryVisibility::Private {
        ensure_fixture_authority(
            database,
            fixture,
            GithubServerServiceScope::PrivateRepositorySourceRead,
            801,
            0x72,
            configured_at,
        )
        .await?;
    }
    let delivery_observed_at = database_now_ms(database).await?;
    let accepted = database
        .store()
        .accept_manifest_pinned_github_delivery(fixture_delivery_request(
            fixture,
            delivery_observed_at,
        )?)
        .await?;
    let claim_observed_at = database_now_ms(database).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(fixture.namespace + 900))?,
            UnixMillis::new(claim_observed_at),
            UnixMillis::new(claim_observed_at + 60_000),
        )?)
        .await?
        .ok_or("accepted fixture delivery was not claimable")?;
    if claimed.claim().delivery_id() != accepted.delivery_id() {
        return Err("the fixture claimed a different provider delivery".into());
    }
    let authenticated_claim = AuthenticatedGithubDeliveryClaim::new(
        claimed.claim(),
        claimed.attempt(),
        claimed.claimed_at(),
        claimed.expires_at(),
    )?;
    let command = logical_command_at(&fixture.command, claimed.claimed_at())?;
    database
        .store()
        .admit_authenticated_github_delivery(
            command.clone(),
            authenticated_claim,
            command.admitted_at(),
        )
        .await?;
    Ok(accepted.check_subject_id().as_uuid())
}

async fn ensure_fixture_authority(
    database: &TestDatabase,
    fixture: &Fixture,
    scope: GithubServerServiceScope,
    id_offset: u128,
    fingerprint: u8,
    observed_at: i64,
) -> TestResult {
    let manifest = &fixture.manifest;
    let identity = GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(fixture.namespace + id_offset))?,
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
        Sha256Digest::from_bytes([fingerprint; 32]),
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            identity,
            UnixMillis::new(observed_at),
        )?)
        .await?;
    Ok(())
}

fn fixture_delivery_request(
    fixture: &Fixture,
    observed_at: i64,
) -> TestResult<AcceptManifestPinnedGithubDelivery> {
    let manifest = &fixture.manifest;
    let identity = ProviderDeliveryIdentity::new(
        manifest.tenant().clone(),
        "github",
        manifest.connection_id(),
        manifest.installation_id(),
        ProviderRepositoryCoordinates::new(
            manifest.github_repository_id(),
            manifest.repository_visibility(),
            manifest.github_repository_name().as_str(),
        )?,
        format!("run-finalization-{}", fixture.namespace),
    )?;
    Ok(AcceptManifestPinnedGithubDelivery::new(
        AcceptProviderDelivery::new(
            identity,
            fixture.command.request_digest(),
            fixture.command.event().clone(),
            UnixMillis::new(observed_at),
        )?,
        ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace)? + 1)?,
        ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace)? + 1)?,
        GithubCheckHeadSha::new([0x14; 20])?,
        manifest.webhook_verifier_fingerprint(),
        manifest.webhook_verifier_revision(),
    )?)
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
    if let Some(concurrency) = command.concurrency() {
        builder = builder.concurrency(Some(concurrency.clone()));
    }
    Ok(builder.build()?)
}

async fn record_concurrency_cancellation(database: &TestDatabase, fixture: &Fixture) -> TestResult {
    let cancelled_at = database_now_ms(database).await?;
    let preempting_run_id = Uuid::from_u128(fixture.namespace + 1_100);
    let mut transaction = database.pool().begin().await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, run_attempt,
            event_name, event_object_key, head_sha, status, created_at_ms, updated_at_ms,
            concurrency_group_key, concurrency_queue_policy, runner_requirements_schema
        )
        SELECT $2, repository_id, workflow_id, snapshot_id, run_number + 1, 1,
               event_name, event_object_key, head_sha, 'queued', $3, $3,
               concurrency_group_key, concurrency_queue_policy, runner_requirements_schema
        FROM workflow_runs
        WHERE id = $1
        ",
    )
    .bind(fixture.command.run_id().as_uuid())
    .bind(preempting_run_id)
    .bind(cancelled_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_concurrency_cancellations (
            run_id, root_invocation_id, preempting_run_id,
            prior_workflow_status, prior_workflow_updated_at_ms,
            prior_marker_state, prior_marker_revision, prior_marker_updated_at_ms,
            prior_invocation_state, prior_invocation_revision,
            prior_invocation_updated_at_ms, cancelled_at_ms
        )
        SELECT run.id, marker.root_invocation_id, $2,
               run.status, run.updated_at_ms,
               marker.state, marker.revision, marker.updated_at_ms,
               invocation.state, invocation.revision, invocation.updated_at_ms, $3
        FROM workflow_runs AS run
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        WHERE run.id = $1
        ",
    )
    .bind(fixture.command.run_id().as_uuid())
    .bind(preempting_run_id)
    .bind(cancelled_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE workflow_runs SET status = 'cancelled', updated_at_ms = $2 WHERE id = $1")
        .bind(fixture.command.run_id().as_uuid())
        .bind(cancelled_at)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

async fn set_linked_check_back_to_queued(database: &TestDatabase, subject_id: Uuid) -> TestResult {
    let mut transaction = database.pool().begin().await?;
    sqlx::query(
        "ALTER TABLE github_check_subjects DISABLE TRIGGER github_check_subjects_update_guard",
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "ALTER TABLE github_check_subjects DISABLE TRIGGER github_check_subjects_wake_projection",
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE github_check_subjects
        SET desired_state = 'queued', desired_revision = 1,
            desired_updated_at_ms = created_at_ms
        WHERE id = $1
        ",
    )
    .bind(subject_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "ALTER TABLE github_check_subjects ENABLE TRIGGER github_check_subjects_wake_projection",
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "ALTER TABLE github_check_subjects ENABLE TRIGGER github_check_subjects_update_guard",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn seed_additional_linked_github_check(
    database: &TestDatabase,
    fixture: &Fixture,
    original_subject_id: Uuid,
    namespace: u128,
) -> TestResult<Uuid> {
    let subject_id = Uuid::from_u128(namespace);
    let mut transaction = database.pool().begin().await?;
    sqlx::query(
        "ALTER TABLE github_check_subjects DISABLE TRIGGER github_check_subjects_00_delivery_evidence_exact",
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO github_check_subjects (
            id, tenant_id, repository_id, provider_delivery_id, subject_key,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_app_id, head_sha, check_name,
            external_id, created_at_ms, desired_updated_at_ms
        )
        SELECT $2, tenant_id, repository_id, provider_delivery_id,
               subject_key || '/duplicate', provider_connection_id,
               provider_installation_id, github_repository_id, github_app_id,
               head_sha, check_name || ' duplicate',
               'automata-check:' || $2::TEXT, 1_401, 1_401
        FROM github_check_subjects
        WHERE id = $1
        ",
    )
    .bind(original_subject_id)
    .bind(subject_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE github_check_subjects
        SET workflow_run_id = $2, linked_at_ms = 1_401,
            desired_state = 'in_progress', desired_revision = 2,
            desired_updated_at_ms = 1_401
        WHERE id = $1
        ",
    )
    .bind(subject_id)
    .bind(fixture.command.run_id().as_uuid())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "ALTER TABLE github_check_subjects ENABLE TRIGGER github_check_subjects_00_delivery_evidence_exact",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(subject_id)
}

async fn claim_two_ready_runs(
    database: &TestDatabase,
) -> TestResult<(ClaimedLogicalRunFinalization, ClaimedLogicalRunFinalization)> {
    let left = fixture("run-finalization-left", 120_000, 1);
    let right = fixture("run-finalization-right", 121_000, 1);
    admit_and_finalize_all_skipped(database, &left).await?;
    admit_and_finalize_all_skipped(database, &right).await?;

    let left_store = database.store().clone();
    let right_store = database.store().clone();
    let left_request = run_claim(database, 122_000, 2_000).await?;
    let right_request = run_claim(database, 122_001, 60_000).await?;
    let (first, second) = tokio::join!(
        left_store.claim_logical_run_finalization(left_request),
        right_store.claim_logical_run_finalization(right_request),
    );
    let first = first?.ok_or("first ready run was not claimed")?;
    let second = second?.ok_or("second ready run was not claimed")?;
    assert_ne!(
        first.descriptor().target().run_id(),
        second.descriptor().target().run_id(),
        "SKIP LOCKED workers must not claim the same marker"
    );
    assert!(
        database
            .store()
            .claim_logical_run_finalization(run_claim(database, 122_002, 60_000).await?)
            .await?
            .is_none(),
        "both ready runs are already fenced"
    );
    Ok((first, second))
}

async fn assert_claimed_graph_and_evidence_are_immutable(
    database: &TestDatabase,
    first: &ClaimedLogicalRunFinalization,
) -> TestResult {
    // The graph-freeze trigger serializes with the marker claim and rejects
    // late source-level jobs before any terminal transition.
    let late_job = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_jobs (
            id, run_id, invocation_id, logical_key, source_order,
            execution_kind, state, activation_fence,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,'late-job',1,'steps','pending',0,1301,1301)
        ",
    )
    .bind(Uuid::from_u128(122_100))
    .bind(first.descriptor().target().run_id().as_uuid())
    .bind(first.descriptor().target().root_invocation_id().as_uuid())
    .execute(database.pool())
    .await;
    assert!(late_job.is_err(), "a claimed run graph must be frozen");

    let original = first.descriptor().jobs()[0].clone();
    let forged_evidence = LogicalRunJobResultEvidence::new(
        original.logical_job_id(),
        original.logical_key().clone(),
        original.source_order(),
        original.descriptor_digest(),
        original.effective_conclusion(),
        original.closure_has_failure(),
        original.closure_has_cancelled(),
        original.closure_has_skipped(),
        original.instance_count(),
        original.instances_digest(),
        original.prerequisite_count(),
        original.prerequisites_digest(),
        original.output_count(),
        original.outputs_digest(),
        Sha256Digest::from_bytes([0xee; 32]),
        original.finalized_at(),
    )?;
    let forged_descriptor = LogicalRunFinalizationDescriptor::new(
        first.descriptor().target().clone(),
        first.descriptor().admission_digest(),
        first.descriptor().marker_state(),
        first.descriptor().marker_revision(),
        first.descriptor().marker_updated_at(),
        first.descriptor().invocation_state(),
        first.descriptor().invocation_revision(),
        first.descriptor().invocation_updated_at(),
        first.descriptor().workflow_status(),
        first.descriptor().workflow_updated_at(),
        vec![forged_evidence],
    )?;
    let forged_fence = LogicalRunFinalizationClaimFence::new(
        forged_descriptor.target().clone(),
        first.claim().owner(),
        first.claim().generation(),
        forged_descriptor.descriptor_digest(),
        first.claim().claimed_at(),
        first.claim().expires_at(),
    )?;
    let forged_claim = ClaimedLogicalRunFinalization::new(forged_descriptor, forged_fence)?;
    let forged_commit = commit_at_claim_start(&forged_claim)?;
    assert!(matches!(
        database
            .store()
            .commit_logical_run_finalization(forged_commit)
            .await,
        Err(LogicalRunFinalizationStoreError::ClaimRejected)
    ));
    Ok(())
}

async fn assert_takeover_replay_and_atomic_terminal_state(
    database: &TestDatabase,
    first: &ClaimedLogicalRunFinalization,
    second: &ClaimedLogicalRunFinalization,
) -> TestResult {
    let second_commit = commit_at_claim_start(second)?;
    database
        .store()
        .commit_logical_run_finalization(second_commit)
        .await?;

    let stale = commit_at_claim_start(first)?;
    wait_until_database_time(database, first.claim().expires_at().get()).await?;
    let takeover = database
        .store()
        .claim_logical_run_finalization(run_claim(database, 122_003, 60_000).await?)
        .await?
        .ok_or("expired run claim was not taken over")?;
    assert_eq!(takeover.descriptor().target(), first.descriptor().target());
    assert_eq!(takeover.claim().generation().get(), 2);
    assert!(matches!(
        database
            .store()
            .commit_logical_run_finalization(stale)
            .await,
        Err(LogicalRunFinalizationStoreError::ClaimRejected)
    ));

    let takeover_commit = commit_at_claim_start(&takeover)?;
    let receipt = database
        .store()
        .commit_logical_run_finalization(takeover_commit.clone())
        .await?;
    assert_eq!(receipt.conclusion(), JobConclusion::Skipped);
    assert!(!receipt.is_replay());
    let replay = database
        .store()
        .commit_logical_run_finalization(takeover_commit)
        .await?;
    assert!(replay.is_replay());
    assert_eq!(replay.commit_digest(), receipt.commit_digest());

    let states: (String, String, String, String) = sqlx::query_as(
        r"
        SELECT invocation.state, marker.state, run.status,
               result.effective_conclusion
        FROM workflow_plan_v2_run_results AS result
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = result.run_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = result.run_id
         AND invocation.id = result.root_invocation_id
        JOIN workflow_runs AS run ON run.id = result.run_id
        WHERE result.run_id = $1
        ",
    )
    .bind(receipt.target().run_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        states,
        (
            "completed".into(),
            "completed".into(),
            "completed".into(),
            "skipped".into()
        )
    );
    assert!(
        sqlx::query(
            "UPDATE workflow_plan_v2_run_results SET effective_conclusion = 'failure' WHERE run_id = $1",
        )
        .bind(receipt.target().run_id().as_uuid())
        .execute(database.pool())
        .await
        .is_err(),
        "aggregate result evidence must be immutable"
    );
    Ok(())
}

async fn admit_and_finalize_all_skipped(database: &TestDatabase, fixture: &Fixture) -> TestResult {
    admit_authenticated_fixture(database, fixture).await?;
    prepare_all_jobs(database, fixture).await?;
    for index in 0..fixture.job_ids.len() {
        finalize_skipped_job(database, fixture, index).await?;
    }
    Ok(())
}

async fn finalize_skipped_job(
    database: &TestDatabase,
    fixture: &Fixture,
    index: usize,
) -> TestResult {
    let logical_job_id = fixture.job_ids[index];
    let owner = job_owner(fixture, index)?;
    let activation = claim_activation(database, fixture, logical_job_id, owner).await?;
    database
        .store()
        .publish_logical_job_activation(automata_ci_store::PublishLogicalJobActivation::new(
            activation.claim().clone(),
            false,
            Vec::new(),
            activation.claim().claimed_at(),
        )?)
        .await?;
    let target = LogicalJobResultTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        logical_job_id,
    )?;
    let result_observed_at = database_now_ms(database).await?;
    let claimed = match database
        .store()
        .claim_logical_job_result(ClaimLogicalJobResult::new(
            target,
            LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(owner + 1_000))?,
            UnixMillis::new(result_observed_at),
            UnixMillis::new(result_observed_at + 60_000),
        )?)
        .await?
    {
        LogicalJobResultClaimOutcome::Claimed(claimed) => claimed,
        other => return Err(format!("logical job result was not ready: {other:?}").into()),
    };
    let commit = CommitLogicalJobResult::new(
        &claimed,
        &fixture.plan_bytes,
        &fixture.plan,
        claimed.claim().claimed_at(),
    )?;
    let receipt = database.store().commit_logical_job_result(commit).await?;
    assert_eq!(receipt.effective_conclusion(), JobConclusion::Skipped);
    Ok(())
}

async fn finalize_rerun_skipped_job(
    database: &TestDatabase,
    fixture: &Fixture,
    run_id: RunId,
    source_order: i32,
) -> TestResult {
    let (invocation_id, logical_job_id): (Uuid, Uuid) = sqlx::query_as(
        r"
        SELECT marker.root_invocation_id, job.id
        FROM workflow_plan_v2_runs AS marker
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = marker.run_id
         AND job.invocation_id = marker.root_invocation_id
        WHERE marker.run_id = $1
          AND job.source_order = $2
          AND NOT job.rerun_carried
        ",
    )
    .bind(run_id.as_uuid())
    .bind(source_order)
    .fetch_one(database.pool())
    .await?;
    let invocation_id = LogicalWorkflowInvocationId::from_uuid(invocation_id)?;
    let logical_job_id = LogicalWorkflowJobId::from_uuid(logical_job_id)?;
    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        run_id,
        invocation_id,
        logical_job_id,
    )?;
    let owner = 0x1260_0000_u128
        + (run_id.as_uuid().as_u128() & 0x000f_ffff) * 4_096
        + u128::try_from(source_order)? * 4;
    let preparation = match select_orchestration(database, &target, owner).await? {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            return Err(format!("expected rerun preparation, got {authority:?}").into());
        }
    };
    database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            preparation.descriptor().clone(),
            preparation.claim().clone(),
            preparation.descriptor().base_context().clone(),
            admission_object(
                format!("run-finalization/rerun-{owner}/needs-context.pb"),
                &[0x72; 64],
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            preparation.claim().claimed_at(),
        )?)
        .await?;
    let activation = match select_orchestration(database, &target, owner + 1).await? {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => claimed,
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            return Err(format!("expected rerun activation, got {authority:?}").into());
        }
    };
    database
        .store()
        .publish_logical_job_activation(automata_ci_store::PublishLogicalJobActivation::new(
            activation.claim().clone(),
            false,
            Vec::new(),
            activation.claim().claimed_at(),
        )?)
        .await?;

    let result_target = LogicalJobResultTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        run_id,
        invocation_id,
        logical_job_id,
    )?;
    let observed_at = database_now_ms(database).await?;
    let claimed = match database
        .store()
        .claim_logical_job_result(ClaimLogicalJobResult::new(
            result_target,
            LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(owner + 2))?,
            UnixMillis::new(observed_at),
            UnixMillis::new(observed_at + 60_000),
        )?)
        .await?
    {
        LogicalJobResultClaimOutcome::Claimed(claimed) => claimed,
        other => return Err(format!("rerun job result was not ready: {other:?}").into()),
    };
    let commit = CommitLogicalJobResult::new(
        &claimed,
        &fixture.plan_bytes,
        &fixture.plan,
        claimed.claim().claimed_at(),
    )?;
    let receipt = database.store().commit_logical_job_result(commit).await?;
    assert_eq!(receipt.effective_conclusion(), JobConclusion::Skipped);
    Ok(())
}

#[allow(clippy::too_many_lines)] // Both late-mutation attacks share one committed fixture.
async fn assert_late_rerun_carry_mutations_are_rejected(
    database: &TestDatabase,
    run_id: RunId,
) -> TestResult {
    let carried_job_id: Uuid = sqlx::query_scalar(
        r"
        SELECT logical_job_id
        FROM workflow_rerun_carried_job_results
        WHERE run_id = $1
        ORDER BY logical_job_id
        LIMIT 1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let timestamp_error = sqlx::query(
        r"
        UPDATE workflow_plan_v2_jobs
        SET updated_at_ms = updated_at_ms + 1
        WHERE id = $1
        ",
    )
    .bind(carried_job_id)
    .execute(database.pool())
    .await
    .expect_err("a carried job timestamp must remain exact after commit");
    assert_eq!(
        timestamp_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("workflow_rerun_carried_job_immutable"),
    );
    let output_error = sqlx::query(
        r"
        INSERT INTO workflow_rerun_carried_job_outputs (
            logical_job_id, output_name, sensitivity, public_value
        ) VALUES ($1, 'forged-late-output', 'public', 'forged')
        ",
    )
    .bind(carried_job_id)
    .execute(database.pool())
    .await
    .expect_err("post-commit carried output insertion must be rejected");
    assert_eq!(
        output_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("workflow_rerun_carried_job_source_exact"),
    );
    let forged_outputs: i64 = sqlx::query_scalar(
        r"
        SELECT count(*)::BIGINT
        FROM workflow_rerun_carried_job_outputs
        WHERE logical_job_id = $1 AND output_name = 'forged-late-output'
        ",
    )
    .bind(carried_job_id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(forged_outputs, 0);

    let selected_job_id: Uuid = sqlx::query_scalar(
        r"
        SELECT logical_job_id
        FROM workflow_rerun_attempt_jobs
        WHERE run_id = $1 AND selected
        ORDER BY logical_job_id
        LIMIT 1
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let carry_error = sqlx::query(
        r"
        INSERT INTO workflow_rerun_carried_job_results (
            logical_job_id, run_id, invocation_id, source_run_id,
            source_logical_job_id, result_descriptor_digest, logical_key,
            source_order, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, activation_output_digest,
            condition_matched, instance_count, instances_digest,
            prerequisite_count, prerequisites_digest, effective_conclusion,
            closure_has_failure, closure_has_cancelled, closure_has_skipped,
            output_count, outputs_digest, commit_digest, claim_owner_id,
            claim_generation, claim_started_at_ms, claim_expires_at_ms,
            finalized_at_ms
        )
        SELECT mapping.logical_job_id, mapping.run_id, job.invocation_id,
               mapping.source_run_id, mapping.source_logical_job_id,
               source.descriptor_digest, source.logical_key,
               source.source_order, source.plan_digest, source.plan_object_key,
               source.plan_size_bytes, source.plan_media_type,
               source.plan_schema, source.activation_output_digest,
               source.condition_matched, source.instance_count,
               source.instances_digest, source.prerequisite_count,
               source.prerequisites_digest, source.effective_conclusion,
               source.closure_has_failure, source.closure_has_cancelled,
               source.closure_has_skipped, source.output_count,
               source.outputs_digest, source.commit_digest,
               source.claim_owner_id, source.claim_generation,
               source.claim_started_at_ms, source.claim_expires_at_ms,
               source.finalized_at_ms
        FROM workflow_rerun_attempt_jobs AS mapping
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = mapping.run_id
         AND job.id = mapping.logical_job_id
        JOIN workflow_plan_v2_effective_job_results AS source
          ON source.run_id = mapping.source_run_id
         AND source.logical_job_id = mapping.source_logical_job_id
         AND source.claim_state = 'finalized'
        WHERE mapping.run_id = $1
          AND mapping.logical_job_id = $2
          AND mapping.selected
        ",
    )
    .bind(run_id.as_uuid())
    .bind(selected_job_id)
    .execute(database.pool())
    .await
    .expect_err("a selected rerun mapping must never gain a carried result");
    assert_eq!(
        carry_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("workflow_rerun_carried_job_exact"),
    );
    let forged_results: i64 = sqlx::query_scalar(
        "SELECT count(*)::BIGINT FROM workflow_rerun_carried_job_results WHERE logical_job_id = $1",
    )
    .bind(selected_job_id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(forged_results, 0);
    Ok(())
}

fn job_owner(fixture: &Fixture, index: usize) -> TestResult<u128> {
    Ok(130_000 + u128::try_from(index)? + (fixture.command.run_id().as_uuid().as_u128() & 0xff))
}

async fn prepare_all_jobs(database: &TestDatabase, fixture: &Fixture) -> TestResult {
    for (index, logical_job_id) in fixture.job_ids.iter().copied().enumerate() {
        prepare_activation(
            database,
            fixture,
            logical_job_id,
            job_owner(fixture, index)?,
        )
        .await?;
    }
    Ok(())
}

async fn prepare_activation(
    database: &TestDatabase,
    fixture: &Fixture,
    logical_job_id: LogicalWorkflowJobId,
    owner: u128,
) -> TestResult<automata_ci_store::LogicalActivationPreparationReceipt> {
    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        logical_job_id,
    )?;
    let preparation = match select_orchestration(database, &target, owner + 10_000).await? {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            return Err(format!("expected preparation authority, got {authority:?}").into());
        }
    };
    Ok(database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            preparation.descriptor().clone(),
            preparation.claim().clone(),
            preparation.descriptor().base_context().clone(),
            admission_object(
                format!("run-finalization/{owner}/needs-context.pb"),
                &[0x52; 64],
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            preparation.claim().claimed_at(),
        )?)
        .await?)
}

async fn claim_activation(
    database: &TestDatabase,
    fixture: &Fixture,
    logical_job_id: LogicalWorkflowJobId,
    owner: u128,
) -> TestResult<ClaimedLogicalJobActivation> {
    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        logical_job_id,
    )?;
    let has_preparation: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM workflow_plan_v2_activation_preparations WHERE logical_job_id = $1)",
    )
    .bind(logical_job_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let expected_input_digest = if has_preparation {
        None
    } else {
        Some(
            prepare_activation(database, fixture, logical_job_id, owner)
                .await?
                .input_digest(),
        )
    };
    match select_orchestration(database, &target, owner).await? {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
            if let Some(expected_input_digest) = expected_input_digest {
                assert_eq!(claimed.claim().input_digest(), expected_input_digest);
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
    owner: u128,
) -> TestResult<ConsumedLogicalJobOrchestrationAuthority> {
    let observed_at = database_now_ms(database).await?;
    let outcome = database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(
                0xa400_0000_0000_0000_0000_0000_0000_0000 | owner,
            ))?,
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(owner))?,
            UnixMillis::new(observed_at),
            60_000,
        )?)
        .await
        .map_err(|error| {
            format!(
                "orchestration selection failed for owner {owner} and target {expected_target:?}: {error:?}"
            )
        })?;
    let selected = match outcome {
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

fn fixture(tenant: &str, namespace: u128, job_count: usize) -> Fixture {
    fixture_with_concurrency(tenant, namespace, job_count, false)
}

fn fixture_with_concurrency(
    tenant: &str,
    namespace: u128,
    job_count: usize,
    concurrency: bool,
) -> Fixture {
    fixture_with_visibility(
        tenant,
        namespace,
        job_count,
        ProviderRepositoryVisibility::Public,
        concurrency,
    )
}

fn fixture_with_visibility(
    tenant: &str,
    namespace: u128,
    job_count: usize,
    visibility: ProviderRepositoryVisibility,
    concurrency: bool,
) -> Fixture {
    fixture_with_visibility_and_dependencies(
        tenant,
        namespace,
        job_count,
        visibility,
        concurrency,
        false,
    )
}

fn fixture_with_visibility_and_dependencies(
    tenant: &str,
    namespace: u128,
    job_count: usize,
    visibility: ProviderRepositoryVisibility,
    concurrency: bool,
    chained: bool,
) -> Fixture {
    fixture_with_options(
        tenant,
        namespace,
        job_count,
        visibility,
        concurrency,
        chained,
        true,
    )
}

#[allow(clippy::too_many_arguments)] // Fixture axes are explicit at call sites.
fn fixture_with_options(
    tenant: &str,
    namespace: u128,
    job_count: usize,
    visibility: ProviderRepositoryVisibility,
    concurrency: bool,
    chained: bool,
    include_base_context: bool,
) -> Fixture {
    let tenant_scope =
        TenantScope::from_authenticated_tenant_id(tenant).expect("authenticated tenant");
    let manifest = fixture_manifest(tenant_scope.clone(), namespace, visibility);
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("invocation");
    let job_ids = (0..job_count)
        .map(|index| {
            LogicalWorkflowJobId::from_uuid(Uuid::from_u128(
                namespace + 10 + u128::try_from(index).expect("small fixture"),
            ))
            .expect("logical job")
        })
        .collect::<Vec<_>>();
    let plan = workflow_plan(job_count, chained);
    let plan_bytes = serde_json::to_vec(&plan).expect("canonical plan");
    let logical_jobs = job_ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            AdmittedLogicalWorkflowJob::new(
                *id,
                WorkflowJobKey::new(format!("job-{index}")).expect("logical key"),
                u16::try_from(index).expect("small fixture"),
                LogicalWorkflowJobKind::Steps,
                if chained && index > 0 {
                    vec![job_ids[index - 1]]
                } else {
                    Vec::new()
                },
            )
            .expect("admitted logical job")
        })
        .collect();
    let mut command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!("run-finalization-{namespace}"))
            .expect("idempotency"),
        Sha256Digest::from_bytes([0x40; 32]),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            namespace.to_string(),
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
            format!("run-finalization/{namespace}/source"),
            &[0x11; 512],
            "application/json",
        ),
        admission_object(
            format!("run-finalization/{namespace}/plan.json"),
            &plan_bytes,
            LOGICAL_JOB_RESULT_PLAN_MEDIA_TYPE,
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(
            format!("run-finalization/{namespace}/event"),
            &[0x13; 512],
            "application/json",
        ),
        vec![0x14; 20],
        logical_jobs,
        UnixMillis::new(1_000),
    );
    if include_base_context {
        command = command.base_context(admission_object(
            format!("run-finalization/{namespace}/base-context"),
            &[0x15; 512],
            "application/vnd.automata.job-runtime-context.protobuf",
        ));
    }
    if concurrency {
        command = command.concurrency(Some(
            WorkflowConcurrency::new("run-finalization", false).expect("concurrency"),
        ));
    }
    let command = command.build().expect("logical admission");
    Fixture {
        tenant: tenant.to_owned(),
        namespace,
        manifest,
        command,
        job_ids,
        plan,
        plan_bytes,
    }
}

fn fixture_manifest(
    tenant: TenantScope,
    namespace: u128,
    visibility: ProviderRepositoryVisibility,
) -> GithubProviderManifest {
    let provider_repository_id = ProviderRepositoryId::new(
        u64::try_from(namespace).expect("fixture namespace fits provider repository ID"),
    )
    .expect("provider repository ID");
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    GithubProviderManifest::new(
        tenant,
        ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 700))
            .expect("provider connection"),
        ProviderInstallationId::new(
            u64::try_from(namespace + 1).expect("fixture installation fits u64"),
        )
        .expect("provider installation"),
        provider_repository_id,
        GithubRepositoryName::new(format!("example/project-{namespace}"))
            .expect("GitHub repository name"),
        visibility,
        GithubServerServiceAppId::new(303).expect("GitHub App ID"),
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("GitHub App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x61; 32]),
        GithubServerServiceRevision::new(1).expect("App configuration revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([0x62; 32]))
            .expect("webhook verifier fingerprint"),
        GithubServerServiceRevision::new(1).expect("webhook verifier revision"),
        GithubServerServiceRevision::new(1).expect("provider policy revision"),
        JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI").expect("GitHub Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1).expect("provider manifest revision"),
    )
}

fn workflow_plan(job_count: usize, chained: bool) -> WorkflowPlan {
    let jobs = (0..job_count)
        .map(|index| {
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
            let mut builder = LogicalJobTemplate::builder(
                located(WorkflowJobKey::new(format!("job-{index}")).expect("job key")),
                u32::try_from(index).expect("small fixture"),
                LogicalJobKind::Steps(StepJobTemplate::new(runner, vec![step], span())),
                span(),
            );
            if chained && index > 0 {
                builder = builder.needs(vec![located(
                    WorkflowJobKey::new(format!("job-{}", index - 1)).expect("need key"),
                )]);
            }
            builder.build().expect("logical job")
        })
        .collect();
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "github",
            "run-finalization.yml",
            PlanSourceOrigin::Memory {
                name: "run-finalization.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
        jobs,
        span(),
    )
    .build()
    .expect("workflow plan")
}

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Run finalization test', 1, 1)",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Explicit relational setup keeps current rerun authority auditable.
async fn seed_rerun_actor(
    database: &TestDatabase,
    tenant: &str,
    repository_id: Uuid,
) -> TestResult<ManagementActor> {
    let principal_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let provider_subject = u64::from(principal_id.as_fields().0).max(1).to_string();
    let provider_login = format!("rerun-actor-{}", principal_id.simple());
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Rerun actor', 1, 1)",
    )
    .bind(principal_id)
    .execute(database.pool())
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
    .bind(&provider_login)
    .execute(database.pool())
    .await?;
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1, $2, 1, 1)",
    )
    .bind(tenant)
    .bind(principal_id)
    .execute(database.pool())
    .await?;
    let role_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id, id, name, display_name, role_kind, immutable,
            created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, 'Workflow rerunner', 'custom', FALSE, $4, 1, 1)
        ",
    )
    .bind(tenant)
    .bind(role_id)
    .bind(format!("workflow-rerunner-{}", role_id.simple()))
    .bind(principal_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO rbac_role_permissions (
            tenant_id, role_id, permission_name,
            granted_by_principal_id, granted_at_ms
        ) VALUES ($1, $2, 'runs:rerun', $3, 1)
        ",
    )
    .bind(tenant)
    .bind(role_id)
    .bind(principal_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id, id, principal_id, role_id, scope_kind, repository_id,
            assignment_source, created_by_principal_id, created_at_ms
        ) VALUES ($1, $2, $3, $4, 'repository', $5, 'manual', $3, 1)
        ",
    )
    .bind(tenant)
    .bind(Uuid::new_v4())
    .bind(principal_id)
    .bind(role_id)
    .bind(repository_id)
    .execute(database.pool())
    .await?;
    let revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(tenant)
    .bind(principal_id)
    .fetch_one(database.pool())
    .await?;
    let now_ms = database_now_ms(database).await?;
    let issued_at = now_ms.saturating_sub(1_000);
    let idle_expires_at = now_ms.checked_add(3_600_000).ok_or("clock overflow")?;
    let expires_at = now_ms.checked_add(7_200_000).ok_or("clock overflow")?;
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
            $1,$2,$3,'github',$4,'browser','automata.web',$5,
            'rerun-session-v1',$6,$7,$7,$8,$9
        )
        ",
    )
    .bind(session_id)
    .bind(tenant)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(token_hash.as_slice())
    .bind(revision)
    .bind(issued_at)
    .bind(idle_expires_at)
    .bind(expires_at)
    .execute(database.pool())
    .await?;
    Ok(ManagementActor::new(
        TenantId::new(tenant)?,
        PrincipalId::new(principal_id.hyphenated().to_string())?,
        SessionId::new(session_id.hyphenated().to_string())?,
        ManagementRevision::new(u64::try_from(revision)?)?,
        None,
        UnixTimestamp::from_seconds(u64::try_from(now_ms / 1_000)?),
    ))
}

async fn run_claim(
    database: &TestDatabase,
    owner: u128,
    duration_ms: i64,
) -> TestResult<ClaimLogicalRunFinalization> {
    let observed_at = database_now_ms(database).await?;
    explicit_run_claim(owner, observed_at, duration_ms)
}

fn explicit_run_claim(
    owner: u128,
    observed_at: i64,
    duration_ms: i64,
) -> TestResult<ClaimLogicalRunFinalization> {
    Ok(ClaimLogicalRunFinalization::new(
        LogicalRunFinalizationWorkerId::from_uuid(Uuid::from_u128(owner)).expect("worker"),
        UnixMillis::new(observed_at),
        UnixMillis::new(
            observed_at
                .checked_add(duration_ms)
                .ok_or("claim time overflow")?,
        ),
    )
    .expect("bounded run claim"))
}

fn commit_at_claim_start(
    claimed: &ClaimedLogicalRunFinalization,
) -> TestResult<CommitLogicalRunFinalization> {
    Ok(CommitLogicalRunFinalization::new(
        claimed,
        claimed.claim().claimed_at(),
    )?)
}

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}

async fn assert_rerun_operation_has_no_writes(
    database: &TestDatabase,
    operation_id: OperationId,
) -> TestResult {
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        r"
        SELECT
            (SELECT count(*) FROM workflow_admission_receipts
             WHERE idempotency_key = $1),
            (SELECT count(*) FROM workflow_rerun_requests
             WHERE operation_id = $2),
            (SELECT count(*) FROM workflow_rerun_audit_evidence
             WHERE operation_id = $2),
            (SELECT count(*) FROM security_audit_events
             WHERE action = 'workflow.rerun'
               AND event_id IN (
                   SELECT event_id FROM workflow_rerun_audit_evidence
                   WHERE operation_id = $2
               ))
        ",
    )
    .bind(format!("workflow-rerun:{operation_id}"))
    .bind(operation_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(counts, (0, 0, 0, 0));
    Ok(())
}

async fn wait_until_database_time(database: &TestDatabase, target: i64) -> TestResult {
    while database_now_ms(database).await? < target {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(())
}

fn admission_object(key: String, bytes: &[u8], media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        ObjectKey::new(key).expect("object key"),
        u64::try_from(bytes.len()).expect("object size"),
        media_type,
    )
    .expect("admission object")
}

fn span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "run-finalization.yml",
        PlanSourceLocation::new(0, 1, 1).expect("location"),
        PlanSourceLocation::new(1, 1, 2).expect("location"),
    )
    .expect("span")
}

fn located<T>(value: T) -> Located<T> {
    Located::new(value, span())
}
