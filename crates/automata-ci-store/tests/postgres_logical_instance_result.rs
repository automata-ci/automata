#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use std::collections::BTreeMap;

use automata_ci_core::{
    Architecture, ContextValue, JobAuthorityProfile, JobConclusion, JobContentReference,
    JobExecutionContext, JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobIrVersion,
    JobOutputDefinition, JobPermissionRequest, JobResult, JobResultOutput, JobRuntimeContext,
    JobSecretExposure, JobSource, OperatingSystem, OperationId, OutputSensitivity, RunId,
    RunValueTemplates, RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    StrategyContext, UnixMillis, ValueTemplate, WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation, CancellationActor,
    CancellationReason, CancellationRepository as _, ClaimLogicalInstanceResult,
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalInstanceResult,
    ClaimNextLogicalJobOrchestration, ClaimProviderDelivery, ClaimedLogicalInstanceMaterialization,
    ClaimedLogicalJobActivation, CommitLogicalInstanceMaterialization, CommitLogicalInstanceResult,
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
    LogicalInstanceMaterializationTarget, LogicalInstanceResultClaimNextOutcome,
    LogicalInstanceResultClaimOutcome, LogicalInstanceResultQuarantineKind,
    LogicalInstanceResultQuarantineOutcome, LogicalInstanceResultRepository as _,
    LogicalInstanceResultSelectionId, LogicalInstanceResultStoreError, LogicalInstanceResultTarget,
    LogicalInstanceResultWorkerId, LogicalJobOrchestrationSelectionOutcome,
    LogicalMaterializationRepository as _, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    LogicalWorkSelectionRepository as _, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind, ObjectKey,
    OpenRunnerSession, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, PublishLogicalJobActivation, QuarantineLogicalInstanceResult,
    RequestCancellation, RoutingDocument, RunnerGeneration, RunnerProtocolVersion,
    RunnerSessionFence, RunnerSessionRepository as _, TenantScope, WorkflowAdmissionIdempotency,
    WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

struct Fixture {
    tenant: String,
    namespace: u128,
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

#[derive(sqlx::FromRow)]
struct ServerCancellationTerminal {
    terminal_authority: String,
    server_cancellation_operation_id: Uuid,
    server_cancellation_digest: Vec<u8>,
    conclusion: String,
    completed_at_ms: i64,
    committed_at_ms: i64,
    workflow_plan_v2_logical_job_id: Uuid,
    workflow_plan_v2_terminal_ordinal: i64,
    has_no_runner_evidence: bool,
    digest_matches_intent: bool,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn queued_cancellation_projects_exact_blob_free_server_authority() -> TestResult {
    run_with_database(|database| async move {
        let (fixture, prepared, attempt_id) =
            seed_materialized_instance_for_cancellation(&database).await?;
        let (operation_id, cancelled_at) =
            request_server_cancellation(&database, attempt_id).await?;
        let terminal_digest = assert_server_cancellation_terminal(
            &database,
            &fixture,
            attempt_id,
            operation_id,
            cancelled_at,
        )
        .await?;
        project_server_cancellation(
            &database,
            &fixture,
            &prepared,
            attempt_id,
            operation_id,
            &terminal_digest,
        )
        .await?;
        Ok(())
    })
    .await
}

async fn seed_materialized_instance_for_cancellation(
    database: &TestDatabase,
) -> TestResult<(Fixture, PreparedInstance, automata_ci_core::AttemptId)> {
    let fixture = fixture(
        "instance-result-server-cancel",
        29_000,
        JobAuthorityProfile::Standard,
    );
    admit_authenticated_fixture(database, &fixture).await?;
    let activation = claim_activation(database, &fixture, 29_100).await?;
    let prepared = prepared_instance(&fixture, &activation, JobAuthorityProfile::Standard);
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            activation.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    let materialized = select_materialization(
        database,
        LogicalInstanceMaterializationTarget::new(
            TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.logical_job_id,
            prepared.activated.id(),
        )?,
        29_200,
    )
    .await?;
    let receipt = database
        .store()
        .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
            &materialized,
            &prepared.encoded,
            &prepared.envelope,
            &prepared.runtime_encoded,
            &prepared.runtime_context,
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    Ok((fixture, prepared, receipt.attempt_id()))
}

async fn request_server_cancellation(
    database: &TestDatabase,
    attempt_id: automata_ci_core::AttemptId,
) -> TestResult<(OperationId, i64)> {
    let operation_id = OperationId::new();
    let cancelled_at = database_now_ms(database).await?;
    let cancellation = RequestCancellation::new(
        operation_id,
        attempt_id,
        CancellationActor::new("scheduler")?,
        Some(CancellationReason::new(
            "logical instance no longer needed",
        )?),
        UnixMillis::new(cancelled_at),
    );
    let first = database
        .store()
        .request_cancellation(cancellation.clone())
        .await?;
    assert!(!first.was_replayed());
    assert!(first.delivery().is_none());
    let replay = database.store().request_cancellation(cancellation).await?;
    assert!(replay.was_replayed());
    assert_eq!(replay.request(), first.request());
    Ok((operation_id, cancelled_at))
}

async fn assert_server_cancellation_terminal(
    database: &TestDatabase,
    fixture: &Fixture,
    attempt_id: automata_ci_core::AttemptId,
    operation_id: OperationId,
    cancelled_at: i64,
) -> TestResult<Vec<u8>> {
    let terminal: ServerCancellationTerminal = sqlx::query_as(
        r"
        SELECT terminal.terminal_authority,
               terminal.server_cancellation_operation_id,
               terminal.server_cancellation_digest,
               terminal.conclusion,
               terminal.completed_at_ms,
               terminal.committed_at_ms,
               terminal.workflow_plan_v2_logical_job_id,
               terminal.workflow_plan_v2_terminal_ordinal,
               num_nonnulls(
                   terminal.runner_session_id, terminal.operation_id,
                   terminal.runner_id, terminal.runner_session_epoch,
                   terminal.runner_generation, terminal.runner_slot,
                   terminal.lease_id, terminal.fencing_token,
                   terminal.result_schema, terminal.result_size_bytes,
                   terminal.result_digest, terminal.result_object_key
               ) = 0 AS has_no_runner_evidence,
               terminal.server_cancellation_digest =
                   automata_server_cancellation_terminal_digest(
                       cancellation.attempt_id, cancellation.operation_id,
                       cancellation.requested_by, cancellation.reason,
                       cancellation.requested_at_ms
                   ) AS digest_matches_intent
        FROM attempt_terminal_results AS terminal
        JOIN attempt_cancellation_intents AS cancellation
          ON cancellation.attempt_id = terminal.attempt_id
         AND cancellation.operation_id = terminal.server_cancellation_operation_id
        WHERE terminal.attempt_id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(terminal.terminal_authority, "server_cancellation");
    assert_eq!(
        terminal.server_cancellation_operation_id,
        operation_id.as_uuid()
    );
    assert_eq!(terminal.server_cancellation_digest.len(), 32);
    assert_eq!(terminal.conclusion, "cancelled");
    assert_eq!(
        (terminal.completed_at_ms, terminal.committed_at_ms),
        (cancelled_at, cancelled_at)
    );
    assert_eq!(
        terminal.workflow_plan_v2_logical_job_id,
        fixture.logical_job_id.as_uuid()
    );
    assert_eq!(terminal.workflow_plan_v2_terminal_ordinal, 1);
    assert!(
        terminal.has_no_runner_evidence,
        "server authority must not contain runner/blob fields"
    );
    assert!(
        terminal.digest_matches_intent,
        "server authority digest must bind the exact intent"
    );
    let due_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_plan_v2_instance_result_due WHERE attempt_id = $1",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        due_count, 1,
        "atomic cancellation must wake projection work"
    );
    Ok(terminal.server_cancellation_digest)
}

async fn project_server_cancellation(
    database: &TestDatabase,
    fixture: &Fixture,
    prepared: &PreparedInstance,
    attempt_id: automata_ci_core::AttemptId,
    operation_id: OperationId,
    terminal_digest: &[u8],
) -> TestResult {
    let observed_at = database_now_ms(database).await?;
    let claimed = expect_result_claimed(
        database
            .store()
            .claim_logical_instance_result(result_claim(
                LogicalInstanceResultTarget::new(
                    TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                    attempt_id,
                )?,
                29_300,
                observed_at,
                observed_at + 3_000,
            ))
            .await?,
    );
    assert!(claimed.descriptor().terminal_result().is_none());
    let server = claimed
        .descriptor()
        .server_cancellation()
        .expect("server cancellation descriptor");
    assert_eq!(server.operation_id(), operation_id);
    assert_eq!(server.digest().as_bytes(), terminal_digest);
    let commit = CommitLogicalInstanceResult::new_server_cancellation(
        &claimed,
        &prepared.encoded,
        &prepared.envelope,
        UnixMillis::new(observed_at + 100),
    )?;
    assert_eq!(commit.raw_conclusion(), JobConclusion::Cancelled);
    assert_eq!(commit.effective_conclusion(), JobConclusion::Cancelled);
    assert!(commit.continue_on_error());
    assert_eq!(commit.secret_exposure(), JobSecretExposure::Secretless);
    assert!(commit.outputs().is_empty());
    let first_receipt = database
        .store()
        .commit_logical_instance_result(commit.clone())
        .await?;
    assert!(!first_receipt.is_replay());
    let replay_receipt = database
        .store()
        .commit_logical_instance_result(commit)
        .await?;
    assert!(replay_receipt.is_replay());
    assert_eq!(
        replay_receipt.commit_digest(),
        first_receipt.commit_digest()
    );
    assert_eq!(replay_receipt.output_count(), 0);
    assert_eq!(
        replay_receipt.secret_exposure(),
        JobSecretExposure::Secretless
    );
    let projected: (String, bool, bool, String, String, String, i32) = sqlx::query_as(
        r"
        SELECT terminal_authority, result_digest IS NULL,
               result_object_key IS NULL, raw_conclusion,
               effective_conclusion, secret_exposure_class, output_count
        FROM workflow_plan_v2_instance_results
        WHERE attempt_id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        projected,
        (
            "server_cancellation".to_owned(),
            true,
            true,
            "cancelled".to_owned(),
            "cancelled".to_owned(),
            "secretless".to_owned(),
            0,
        )
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn terminal_projection_is_fenced_replayable_and_secret_safe() -> TestResult {
    run_with_database(|database| async move {
        let idle_observed_at = database_now_ms(&database).await?;
        let idle_request = ClaimNextLogicalInstanceResult::new(
            LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(30_390))?,
            LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(30_391))?,
            UnixMillis::new(idle_observed_at),
            UnixMillis::new(idle_observed_at + 60_000),
        )?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left_idle, right_idle) = tokio::join!(
            left_store.claim_next_logical_instance_result(idle_request.clone()),
            right_store.claim_next_logical_instance_result(idle_request.clone()),
        );
        assert!(matches!(left_idle?, LogicalInstanceResultClaimNextOutcome::Idle));
        assert!(matches!(right_idle?, LogicalInstanceResultClaimNextOutcome::Idle));

        let fixture = fixture(
            "instance-result-main",
            30_000,
            JobAuthorityProfile::Standard,
        );
        admit_authenticated_fixture(&database, &fixture).await?;
        let activation = claim_activation(&database, &fixture, 30_100).await?;
        let prepared = prepared_instance(&fixture, &activation, JobAuthorityProfile::Standard);
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                activation.claim().clone(),
                true,
                vec![prepared.activated.clone()],
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        let materialized = select_materialization(
            &database,
            LogicalInstanceMaterializationTarget::new(
                TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                fixture.command.run_id(),
                fixture.command.root_invocation_id(),
                fixture.logical_job_id,
                prepared.activated.id(),
            )?,
            30_200,
        )
        .await?;
        let materialization_receipt = database
            .store()
            .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
                &materialized,
                &prepared.encoded,
                &prepared.envelope,
                &prepared.runtime_encoded,
                &prepared.runtime_context,
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;

        let session = open_runner(&database, &fixture.tenant, 30_300).await?;
        let terminal_completed_at = database_now_ms(&database).await?;
        let result = JobResult::new(
            materialization_receipt.attempt_id(),
            JobConclusion::Failure,
            JobSecretExposure::ReadableSecret,
            UnixMillis::new(terminal_completed_at),
        )
        .with_outputs(BTreeMap::from([
            (
                "artifact".to_owned(),
                JobResultOutput::public("bundle-42")?,
            ),
            ("masked".to_owned(), JobResultOutput::secret_derived()),
        ]));
        result.validate()?;
        let result_bytes = serde_json::to_vec(&result)?;
        seed_terminal_result(
            &database,
            session,
            materialization_receipt.attempt_id(),
            &result_bytes,
            terminal_completed_at,
        )
        .await?;
        assert!(
            sqlx::query(
                "UPDATE attempt_terminal_results SET result_digest = $2 WHERE attempt_id = $1",
            )
            .bind(materialization_receipt.attempt_id().as_uuid())
            .bind(vec![0xA5_u8; 32])
            .execute(database.pool())
            .await
            .is_err(),
            "terminal result evidence cannot be rewritten after admission"
        );
        assert!(
            sqlx::query("DELETE FROM attempt_terminal_results WHERE attempt_id = $1")
                .bind(materialization_receipt.attempt_id().as_uuid())
                .execute(database.pool())
                .await
                .is_err(),
            "retained terminal result evidence cannot be deleted"
        );
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_materialization_claims WHERE instance_id = $1",
            )
            .bind(prepared.activated.id().as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "the exact materialization claim remains retained for projection"
        );
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_concrete_jobs WHERE initial_attempt_id = $1",
            )
            .bind(materialization_receipt.attempt_id().as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "the exact logical-to-concrete mapping remains retained for projection"
        );
        let due_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_instance_result_due WHERE attempt_id = $1",
        )
        .bind(materialization_receipt.attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(due_count, 1);
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_instance_result_due WHERE attempt_id = $1",
            )
            .bind(materialization_receipt.attempt_id().as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "the trigger-authoritative instance due row cannot be deleted"
        );
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(idle_request.clone())
                .await?,
            LogicalInstanceResultClaimNextOutcome::Idle
        ));

        let target = LogicalInstanceResultTarget::new(
            TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
            materialization_receipt.attempt_id(),
        )?;
        let first_observed_at = database_now_ms(&database).await?;
        let first_expires_at = first_observed_at + 3_000;
        let first_request = ClaimNextLogicalInstanceResult::new(
            LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(30_399))?,
            LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(30_400))?,
            UnixMillis::new(first_observed_at),
            UnixMillis::new(first_expires_at),
        )?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.claim_next_logical_instance_result(first_request.clone()),
            right_store.claim_next_logical_instance_result(first_request.clone()),
        );
        let (first, replay) = match (left?, right?) {
            (
                LogicalInstanceResultClaimNextOutcome::Claimed(left),
                LogicalInstanceResultClaimNextOutcome::Claimed(right),
            ) if left.claim() == right.claim() && left.is_replay() != right.is_replay() => {
                if left.is_replay() {
                    (right, left)
                } else {
                    (left, right)
                }
            }
            outcomes => panic!("equal-ID instance claims must replay exactly: {outcomes:?}"),
        };
        assert_eq!(first.claim().generation().get(), 1);
        assert_eq!(first.descriptor().job_id(), materialization_receipt.job_id());
        assert_eq!(first.descriptor().raw_conclusion(), JobConclusion::Failure);
        assert_eq!(first.descriptor().terminal_ordinal().get(), 1);
        assert_eq!(
            first
                .descriptor()
                .terminal_result()
                .expect("runner terminal evidence")
                .digest(),
            Sha256Digest::from_bytes(Sha256::digest(&result_bytes).into())
        );
        assert_eq!(first.descriptor().job_ir().digest(), prepared.activated.job_ir().digest());
        assert!(replay.is_replay());
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(ClaimNextLogicalInstanceResult::new(
                    first_request.selection_id(),
                    LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(30_498))?,
                    first_request.observed_at(),
                    first_request.expires_at(),
                )?)
                .await,
            Err(LogicalInstanceResultStoreError::SelectionConflict)
        ));
        assert!(matches!(
            database
                .store()
                .claim_logical_instance_result(result_claim(
                    target.clone(),
                    30_401,
                    first_observed_at + 100,
                    first_expires_at + 100,
                ))
                .await?,
            LogicalInstanceResultClaimOutcome::Busy
        ));

        let stale_commit = CommitLogicalInstanceResult::new(
            &first,
            &result_bytes,
            &result,
            &prepared.encoded,
            &prepared.envelope,
            UnixMillis::new(first_observed_at + 200),
        )?;
        wait_until_database_after(&database, first_expires_at).await?;
        assert!(matches!(
            database
                .store()
                .quarantine_logical_instance_result(QuarantineLogicalInstanceResult::new(
                    &first,
                    LogicalInstanceResultQuarantineKind::ObjectEvidence,
                ))
                .await?,
            LogicalInstanceResultQuarantineOutcome::FenceRejected
        ));
        let takeover = expect_result_claimed(
            database
                .store()
                .claim_logical_instance_result(result_claim(
                    target.clone(),
                    30_402,
                    first_expires_at,
                    first_expires_at + 3_000,
                ))
                .await?,
        );
        assert_eq!(takeover.claim().generation().get(), 2);
        let quarantine = QuarantineLogicalInstanceResult::new(
            &takeover,
            LogicalInstanceResultQuarantineKind::PayloadEvidence,
        );
        assert!(matches!(
            database
                .store()
                .quarantine_logical_instance_result(quarantine.clone())
                .await?,
            LogicalInstanceResultQuarantineOutcome::Quarantined
        ));
        assert!(matches!(
            database
                .store()
                .quarantine_logical_instance_result(quarantine)
                .await?,
            LogicalInstanceResultQuarantineOutcome::AlreadyQuarantined
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(first_request)
                .await,
            Err(LogicalInstanceResultStoreError::SelectionExpired)
        ));
        assert!(
            sqlx::query(
                "UPDATE workflow_plan_v2_instance_result_selections SET owner_id = $2 WHERE selection_id = $1",
            )
            .bind(Uuid::from_u128(30_399))
            .bind(Uuid::from_u128(30_499))
            .execute(database.pool())
            .await
            .is_err(),
            "global selection receipts are immutable"
        );
        assert!(matches!(
            database
                .store()
                .commit_logical_instance_result(stale_commit)
                .await,
            Err(LogicalInstanceResultStoreError::ClaimRejected)
        ));

        let current_commit = CommitLogicalInstanceResult::new(
            &takeover,
            &result_bytes,
            &result,
            &prepared.encoded,
            &prepared.envelope,
            UnixMillis::new(first_expires_at + 500),
        )?;
        assert_eq!(
            current_commit.effective_conclusion(),
            JobConclusion::Success,
            "job-level continue-on-error maps only the logical conclusion"
        );
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.commit_logical_instance_result(current_commit.clone()),
            right_store.commit_logical_instance_result(current_commit),
        );
        let left = left?;
        let right = right?;
        assert_ne!(left.is_replay(), right.is_replay());
        assert_eq!(left.commit_digest(), right.commit_digest());
        assert_eq!(left.output_count(), 2);
        assert_eq!(left.terminal_ordinal().get(), 1);
        assert_eq!(left.secret_exposure(), JobSecretExposure::ReadableSecret);
        let due_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_instance_result_due WHERE attempt_id = $1",
        )
        .bind(materialization_receipt.attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(due_count, 0, "finalization removes the bounded due row");
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_instance_result_claims WHERE attempt_id = $1",
            )
            .bind(materialization_receipt.attempt_id().as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "finalized instance fences cannot be deleted"
        );
        assert!(matches!(
            database
                .store()
                .claim_logical_instance_result(result_claim(
                    target,
                    30_403,
                    first_expires_at + 600,
                    first_expires_at + 3_100,
                ))
                .await?,
            LogicalInstanceResultClaimOutcome::Finalized(receipt)
                if receipt.is_replay() && receipt.commit_digest() == left.commit_digest()
        ));

        let outputs: Vec<(String, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT output_name, sensitivity, public_value
            FROM workflow_plan_v2_instance_result_outputs
            WHERE instance_id = $1
            ORDER BY output_name COLLATE "C"
            "#,
        )
        .bind(prepared.activated.id().as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(
            outputs,
            vec![
                (
                    "artifact".to_owned(),
                    "public".to_owned(),
                    Some("bundle-42".to_owned()),
                ),
                ("masked".to_owned(), "secret_derived".to_owned(), None),
            ]
        );
        let result_contract: (String, String) = sqlx::query_as(
            "SELECT secret_exposure_class, result_media_type FROM workflow_plan_v2_instance_results WHERE instance_id = $1",
        )
        .bind(prepared.activated.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            result_contract,
            (
                "readable_secret".to_owned(),
                "application/vnd.automata.job-result+json".to_owned(),
            )
        );
        assert!(
            sqlx::query(
                "UPDATE workflow_plan_v2_instance_results SET effective_conclusion = 'failure' WHERE instance_id = $1",
            )
            .bind(prepared.activated.id().as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "finalized instance evidence must be immutable"
        );
        assert!(
            sqlx::query(
                "DELETE FROM workflow_plan_v2_instance_result_outputs WHERE instance_id = $1",
            )
            .bind(prepared.activated.id().as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "instance child evidence cannot be deleted"
        );
        assert!(
            sqlx::query("TRUNCATE workflow_plan_v2_instance_result_outputs")
                .execute(database.pool())
                .await
                .is_err(),
            "instance child evidence cannot be truncated"
        );
        let short_idle_observed_at = database_now_ms(&database).await?;
        let short_idle_request = ClaimNextLogicalInstanceResult::new(
            LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(30_690))?,
            LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(30_691))?,
            UnixMillis::new(short_idle_observed_at),
            UnixMillis::new(short_idle_observed_at + 100),
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(short_idle_request.clone())
                .await?,
            LogicalInstanceResultClaimNextOutcome::Idle
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
                .claim_next_logical_instance_result(ClaimNextLogicalInstanceResult::new(
                    LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(30_700))?,
                    LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(30_701))?,
                    UnixMillis::new(cleanup_observed_at),
                    UnixMillis::new(cleanup_observed_at + 1_000),
                )?)
                .await?,
            LogicalInstanceResultClaimNextOutcome::Idle
        ));
        let old_idle_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_instance_result_selections WHERE selection_id = $1",
        )
        .bind(short_idle_request.selection_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            old_idle_count, 0,
            "expired Idle receipts are cleaned in bounded batches"
        );
        let old_claimed_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_instance_result_selections WHERE selection_id = $1",
        )
        .bind(Uuid::from_u128(30_399))
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            old_claimed_count, 0,
            "expired Claimed receipts are cleaned after replay closes"
        );
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(short_idle_request)
                .await,
            Err(LogicalInstanceResultStoreError::SelectionExpired)
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(ClaimNextLogicalInstanceResult::new(
                    LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(30_702))?,
                    LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(30_703))?,
                    UnixMillis::new(cleanup_observed_at + 120_000),
                    UnixMillis::new(cleanup_observed_at + 121_000),
                )?)
                .await,
            Err(LogicalInstanceResultStoreError::SelectionClockSkew)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One live path binds admission safety to terminal persistence.
async fn credential_free_attempt_accepts_and_persists_secretless_terminal_exposure() -> TestResult {
    run_with_database(|database| async move {
        let fixture = fixture(
            "instance-result-credential-free",
            31_000,
            JobAuthorityProfile::CredentialFree,
        );
        admit_authenticated_fixture(&database, &fixture).await?;
        let activation = claim_activation(&database, &fixture, 31_100).await?;
        let prepared = prepared_instance(
            &fixture,
            &activation,
            JobAuthorityProfile::CredentialFree,
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
        let materialized = select_materialization(
            &database,
            LogicalInstanceMaterializationTarget::new(
                TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                fixture.command.run_id(),
                fixture.command.root_invocation_id(),
                fixture.logical_job_id,
                prepared.activated.id(),
            )?,
            31_200,
        )
        .await?;
        let materialization_receipt = database
            .store()
            .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
                &materialized,
                &prepared.encoded,
                &prepared.envelope,
                &prepared.runtime_encoded,
                &prepared.runtime_context,
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        let attempt_safety: (String, String) = sqlx::query_as(
            r"
            SELECT secret_exposure_class, raw_log_disposition
            FROM job_attempts WHERE id = $1
            ",
        )
        .bind(materialization_receipt.attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            attempt_safety,
            ("secretless".to_owned(), "persist".to_owned())
        );

        let session = open_runner(&database, &fixture.tenant, 31_300).await?;
        let terminal_completed_at = database_now_ms(&database).await?;
        let result = JobResult::new(
            materialization_receipt.attempt_id(),
            JobConclusion::Failure,
            JobSecretExposure::Secretless,
            UnixMillis::new(terminal_completed_at),
        )
        .with_outputs(BTreeMap::from([
            (
                "artifact".to_owned(),
                JobResultOutput::public("bundle-42")?,
            ),
            (
                "masked".to_owned(),
                JobResultOutput::public("ordinary-value")?,
            ),
        ]));
        result.validate()?;
        let result_bytes = serde_json::to_vec(&result)?;
        seed_terminal_result(
            &database,
            session,
            materialization_receipt.attempt_id(),
            &result_bytes,
            terminal_completed_at,
        )
        .await?;
        let projection_observed_at = database_now_ms(&database).await?;
        let claimed = expect_result_claimed(
            database
                .store()
                .claim_logical_instance_result(result_claim(
                    LogicalInstanceResultTarget::new(
                        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
                        materialization_receipt.attempt_id(),
                    )?,
                    31_400,
                    projection_observed_at,
                    projection_observed_at + 3_000,
                ))
                .await?,
        );
        assert_eq!(
            claimed.descriptor().maximum_secret_exposure(),
            JobSecretExposure::Secretless
        );
        let receipt = database
            .store()
            .commit_logical_instance_result(CommitLogicalInstanceResult::new(
                &claimed,
                &result_bytes,
                &result,
                &prepared.encoded,
                &prepared.envelope,
                UnixMillis::new(projection_observed_at + 500),
            )?)
            .await?;
        assert_eq!(receipt.secret_exposure(), JobSecretExposure::Secretless);
        let persisted: String = sqlx::query_scalar(
            "SELECT secret_exposure_class FROM workflow_plan_v2_instance_results WHERE instance_id = $1",
        )
        .bind(prepared.activated.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(persisted, "secretless");
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
        let request = ClaimNextLogicalInstanceResult::new(
            LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(31_800))?,
            LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(31_801))?,
            UnixMillis::new(observed_at),
            UnixMillis::new(observed_at + 300_000),
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(request.clone())
                .await?,
            LogicalInstanceResultClaimNextOutcome::Idle
        ));

        assert!(
            sqlx::query(
                r"
                UPDATE workflow_plan_v2_result_selection_replay_horizons
                SET replay_floor_ms = $1, updated_at_ms = $1
                WHERE queue_name = 'instance'
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
                .claim_next_logical_instance_result(request.clone())
                .await?,
            LogicalInstanceResultClaimNextOutcome::Idle
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(ClaimNextLogicalInstanceResult::new(
                    LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(31_802))?,
                    request.owner(),
                    request.observed_at(),
                    request.expires_at(),
                )?)
                .await,
            Err(LogicalInstanceResultStoreError::SelectionClockSkew)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn corrupt_oldest_instance_is_quarantined_and_newer_work_continues() -> TestResult {
    run_with_database(|database| async move {
        let older = fixture(
            "instance-result-poison-older",
            32_000,
            JobAuthorityProfile::Standard,
        );
        let newer = fixture(
            "instance-result-poison-newer",
            33_000,
            JobAuthorityProfile::Standard,
        );
        let (older_instance, older_attempt) =
            seed_ready_terminal_instance(&database, &older, 32_100).await?;
        let (_newer_instance, newer_attempt) =
            seed_ready_terminal_instance(&database, &newer, 33_100).await?;

        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instances DISABLE TRIGGER workflow_plan_v2_instances_reject_update",
        )
        .execute(database.pool())
        .await?;
        sqlx::query("UPDATE workflow_plan_v2_instances SET job_ir_digest = $2 WHERE id = $1")
            .bind(older_instance.activated.id().as_uuid())
            .bind(vec![0xA5_u8; 32])
            .execute(database.pool())
            .await?;
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_instances ENABLE TRIGGER workflow_plan_v2_instances_reject_update",
        )
        .execute(database.pool())
        .await?;

        let observed_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_result(ClaimNextLogicalInstanceResult::new(
                    LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(34_000))?,
                    LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(34_001))?,
                    UnixMillis::new(observed_at),
                    UnixMillis::new(observed_at + 3_000),
                )?)
                .await?,
            LogicalInstanceResultClaimNextOutcome::Quarantined
        ));
        let quarantine: (String, String, bool) = sqlx::query_as(
            r"
            SELECT tenant_id, failure_kind, claim_owner_id IS NULL
            FROM workflow_plan_v2_instance_result_quarantines
            WHERE attempt_id = $1
            ",
        )
        .bind(older_attempt.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            quarantine,
            (older.tenant.clone(), "relational_evidence".to_owned(), true)
        );
        assert!(
            sqlx::query(
                "UPDATE workflow_plan_v2_instance_result_quarantines SET failure_kind = 'object_evidence' WHERE attempt_id = $1",
            )
            .bind(older_attempt.as_uuid())
            .execute(database.pool())
            .await
            .is_err(),
            "the observable quarantine ledger is immutable"
        );
        let due_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_instance_result_due WHERE attempt_id = $1",
        )
        .bind(older_attempt.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(due_count, 1, "quarantine cannot launder the poisoned target");

        let next_observed_at = database_now_ms(&database).await?;
        let next = database
            .store()
            .claim_next_logical_instance_result(ClaimNextLogicalInstanceResult::new(
                LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(34_002))?,
                LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(34_003))?,
                UnixMillis::new(next_observed_at),
                UnixMillis::new(next_observed_at + 3_000),
            )?)
            .await?;
        assert!(matches!(
            next,
            LogicalInstanceResultClaimNextOutcome::Claimed(claimed)
                if claimed.claim().target().attempt_id() == newer_attempt
        ));
        Ok(())
    })
    .await
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

fn fixture(tenant: &str, namespace: u128, authority_profile: JobAuthorityProfile) -> Fixture {
    let tenant_scope = TenantScope::from_authenticated_tenant_id(tenant).expect("tenant");
    let repository_visibility = match authority_profile {
        JobAuthorityProfile::Standard => ProviderRepositoryVisibility::Private,
        JobAuthorityProfile::CredentialFree => ProviderRepositoryVisibility::Public,
    };
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new(
        tenant_scope.clone(),
        ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 20)).expect("connection"),
        ProviderInstallationId::new(u64::try_from(namespace + 100).expect("installation"))
            .expect("installation"),
        ProviderRepositoryId::new(u64::try_from(namespace + 101).expect("repository"))
            .expect("repository"),
        GithubRepositoryName::new(format!("example/project-{namespace}")).expect("repository name"),
        repository_visibility,
        GithubServerServiceAppId::new(u64::try_from(namespace + 102).expect("app ID"))
            .expect("app ID"),
        GithubServerServiceAppClientId::new(format!("Iv1.result{namespace}")).expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x71; 32]),
        GithubServerServiceRevision::new(1).expect("configuration revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([0x72; 32]))
            .expect("webhook verifier fingerprint"),
        GithubServerServiceRevision::new(1).expect("webhook revision"),
        GithubServerServiceRevision::new(1).expect("policy revision"),
        authority_profile,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI").expect("check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1).expect("manifest revision"),
    );
    let repository_id = manifest.repository_id();
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("invocation");
    let logical_job_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("logical job");
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
        WorkflowAdmissionIdempotency::provider_delivery(format!("result-{namespace}"))
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
        admission_object(format!("instance-result/{namespace}/source"), 0x11),
        admission_object_with_media(
            format!("instance-result/{namespace}/plan"),
            0x12,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(format!("instance-result/{namespace}/event"), 0x13),
        vec![0x14; 20],
        vec![logical_job],
        UnixMillis::new(1_000),
    )
    .base_context(admission_object_with_media(
        format!("instance-result/{namespace}/base-context"),
        0x15,
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
    }
}

async fn admit_authenticated_fixture(database: &TestDatabase, fixture: &Fixture) -> TestResult {
    let namespace = fixture.namespace;
    let manifest = &fixture.manifest;
    let tenant = manifest.tenant().clone();
    let connection = manifest.connection_id();
    let installation = manifest.installation_id();
    let github_repository = manifest.github_repository_id();
    let repository_visibility = manifest.repository_visibility();
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
    ensure_instance_result_server_authorities(database, fixture, configured_at).await?;
    let delivery_observed_at = database_now_ms(database).await?;
    let accepted = database
        .store()
        .accept_manifest_pinned_github_delivery(AcceptManifestPinnedGithubDelivery::new(
            AcceptProviderDelivery::new(
                ProviderDeliveryIdentity::new(
                    tenant,
                    "github",
                    connection,
                    installation,
                    ProviderRepositoryCoordinates::new(
                        github_repository,
                        repository_visibility,
                        format!("example/project-{namespace}"),
                    )?,
                    format!("instance-result-{namespace}"),
                )?,
                fixture.command.request_digest(),
                fixture.command.event().clone(),
                UnixMillis::new(delivery_observed_at),
            )?,
            ProviderRepositoryOwnerId::new(u64::try_from(namespace + 103)?)?,
            ProviderRepositoryOwnerId::new(u64::try_from(namespace + 103)?)?,
            GithubCheckHeadSha::new([0x14; 20])?,
            fixture.manifest.webhook_verifier_fingerprint(),
            fixture.manifest.webhook_verifier_revision(),
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
    let authenticated = AuthenticatedGithubDeliveryClaim::new(
        claimed.claim(),
        claimed.attempt(),
        claimed.claimed_at(),
        claimed.expires_at(),
    )?;
    let command = logical_command_at(&fixture.command, claimed.claimed_at())?;
    database
        .store()
        .admit_authenticated_github_delivery(command.clone(), authenticated, command.admitted_at())
        .await?;
    Ok(())
}

async fn ensure_instance_result_server_authorities(
    database: &TestDatabase,
    fixture: &Fixture,
    configured_at: i64,
) -> TestResult {
    let manifest = &fixture.manifest;
    let authority = |id_offset, scope, digest| {
        GithubServerServiceAuthorityIdentity::new(
            manifest.tenant().clone(),
            GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(
                fixture.namespace + id_offset,
            ))?,
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
            Sha256Digest::from_bytes([digest; 32]),
        )
    };
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            authority(21, GithubServerServiceScope::ChecksWrite, 0x73)?,
            UnixMillis::new(configured_at),
        )?)
        .await?;
    if manifest.repository_visibility() == ProviderRepositoryVisibility::Private {
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                authority(
                    23,
                    GithubServerServiceScope::PrivateRepositorySourceRead,
                    0x75,
                )?,
                UnixMillis::new(configured_at),
            )?)
            .await?;
    }
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
            admission_object_with_media(
                format!("instance-result/{owner}/needs-context.pb"),
                0x52,
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
                0xa100_0000_0000_0000_0000_0000_0000_0000 | owner,
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
                0xb100_0000_0000_0000_0000_0000_0000_0000 | owner,
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

#[allow(clippy::too_many_lines)] // Synthetic JobIR binds every current projection field.
fn prepared_instance(
    fixture: &Fixture,
    claimed: &ClaimedLogicalJobActivation,
    authority_profile: JobAuthorityProfile,
) -> PreparedInstance {
    let matrix_digest = Sha256Digest::from_bytes([0x77; 32]);
    let job_id = deterministic_job_id(
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
        matrix_digest,
    );
    let identity = JobInstanceIdentity::new(claimed.logical_key().as_str(), 0, 1, matrix_digest)
        .expect("matrix identity");
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
    let runtime_encoded = serde_json::to_vec(&runtime_context).expect("encoded runtime context");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes(Sha256::digest(&runtime_encoded).into()),
        ObjectKey::new("instance-result/runtime.pb").expect("runtime key"),
        u64::try_from(runtime_encoded.len()).expect("runtime size"),
    )
    .expect("runtime object");
    let step = StepIr::new_literal_name(
        StepId::new("run").expect("step ID"),
        "Run",
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("false").expect("command"),
            ShellTemplate::default_shell(),
        )),
    )
    .expect("step");
    let definitions = [
        ("artifact", OutputSensitivity::Public),
        ("masked", OutputSensitivity::Public),
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
    let mut job = JobIr::new(
        job_id,
        fixture.command.run_id(),
        "Build",
        RunnerRequirements::default(),
        identity.clone(),
        true,
        vec![step],
    )
    .with_output_definitions(definitions)
    .with_authority_profile(authority_profile);
    if authority_profile == JobAuthorityProfile::CredentialFree {
        job = job.with_permission_request(JobPermissionRequest::mapping([]));
    }
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
            "0123456789abcdef",
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
            ObjectKey::new("instance-result/job-ir.pb").expect("JobIR key"),
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
        ) VALUES ($1,$2,'result-runner','result-runner',$3::jsonb,1,'online','active',1,1)
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

struct TerminalResultSeed<'a> {
    session: &'a RunnerSessionFence,
    attempt_id: automata_ci_core::AttemptId,
    result_bytes: &'a [u8],
    lease_id: Uuid,
    lease_issued_at: i64,
    lease_expires_at: i64,
    completed_at: i64,
    committed_at: i64,
}

async fn seed_terminal_result(
    database: &TestDatabase,
    session: RunnerSessionFence,
    attempt_id: automata_ci_core::AttemptId,
    result_bytes: &[u8],
    completed_at: i64,
) -> TestResult {
    let seed = TerminalResultSeed {
        session: &session,
        attempt_id,
        result_bytes,
        lease_id: Uuid::from_u128(30_501),
        lease_issued_at: completed_at,
        lease_expires_at: completed_at + 60_000,
        completed_at,
        committed_at: completed_at,
    };
    let mut transaction = database.pool().begin().await?;

    activate_terminal_attempt(&mut transaction, &seed).await?;
    insert_runner_terminal_result(&mut transaction, &seed).await?;
    let before_terminal_lifecycle =
        instance_result_projection_counts(&mut transaction, &seed).await?;
    assert_eq!(
        before_terminal_lifecycle,
        (0, 0),
        "inserting terminal evidence while the attempt is active cannot publish projection work"
    );
    terminalize_attempt(&mut transaction, &seed).await?;
    let after_terminal_lifecycle =
        instance_result_projection_counts(&mut transaction, &seed).await?;
    assert_eq!(
        after_terminal_lifecycle,
        (1, 0),
        "the terminal lifecycle transition must wake exactly one unclaimed due target"
    );
    transaction.commit().await?;
    Ok(())
}

async fn activate_terminal_attempt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    seed: &TerminalResultSeed<'_>,
) -> TestResult {
    let activated = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'running', fencing_token = 1, lease_id = $2,
            runner_id = $3, lease_issued_at_ms = $7,
            lease_expires_at_ms = $8, runner_session_id = $4,
            runner_session_epoch = $5, runner_generation = $6,
            runner_slot = 1, changed_at_ms = $7
        WHERE id = $1 AND lifecycle = 'queued'
        ",
    )
    .bind(seed.attempt_id.as_uuid())
    .bind(seed.lease_id)
    .bind(seed.session.runner_id().as_uuid())
    .bind(seed.session.session_id().as_uuid())
    .bind(i64::try_from(seed.session.session_epoch().get())?)
    .bind(i64::try_from(seed.session.runner_generation().get())?)
    .bind(seed.lease_issued_at)
    .bind(seed.lease_expires_at)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    assert_eq!(activated, 1, "the queued attempt must become active once");
    Ok(())
}

async fn insert_runner_terminal_result(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    seed: &TerminalResultSeed<'_>,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, terminal_authority,
            runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, result_schema, result_size_bytes,
            result_digest, result_object_key, conclusion,
            completed_at_ms, committed_at_ms
        ) VALUES ($1,'runner',$2,$3,$4,$5,$6,1,$7,1,1,$8,$9,$10,'failure',$11,$12)
        ",
    )
    .bind(seed.attempt_id.as_uuid())
    .bind(seed.session.session_id().as_uuid())
    .bind(Uuid::from_u128(30_500))
    .bind(seed.session.runner_id().as_uuid())
    .bind(i64::try_from(seed.session.session_epoch().get())?)
    .bind(i64::try_from(seed.session.runner_generation().get())?)
    .bind(seed.lease_id)
    .bind(i64::try_from(seed.result_bytes.len())?)
    .bind(Sha256::digest(seed.result_bytes).as_slice())
    .bind("instance-result/terminal.json")
    .bind(seed.completed_at)
    .bind(seed.committed_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn instance_result_projection_counts(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    seed: &TerminalResultSeed<'_>,
) -> TestResult<(i64, i64)> {
    let counts = sqlx::query_as(
        r"
        SELECT
            (SELECT count(*) FROM workflow_plan_v2_instance_result_due
             WHERE attempt_id = $1),
            (SELECT count(*) FROM workflow_plan_v2_instance_result_claims
             WHERE attempt_id = $1)
        ",
    )
    .bind(seed.attempt_id.as_uuid())
    .fetch_one(&mut **transaction)
    .await?;
    Ok(counts)
}

async fn terminalize_attempt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    seed: &TerminalResultSeed<'_>,
) -> TestResult {
    let transitioned = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'failed', lease_id = NULL, runner_id = NULL,
            lease_issued_at_ms = NULL, lease_expires_at_ms = NULL,
            runner_session_id = NULL, runner_session_epoch = NULL,
            runner_generation = NULL, runner_slot = NULL, changed_at_ms = $3
        WHERE id = $1 AND lifecycle = 'running' AND lease_id = $2
        ",
    )
    .bind(seed.attempt_id.as_uuid())
    .bind(seed.lease_id)
    .bind(seed.committed_at)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    assert_eq!(transitioned, 1, "the active attempt must terminalize once");
    Ok(())
}

async fn seed_ready_terminal_instance(
    database: &TestDatabase,
    fixture: &Fixture,
    identity: u128,
) -> TestResult<(PreparedInstance, automata_ci_core::AttemptId)> {
    admit_authenticated_fixture(database, fixture).await?;
    let activation = claim_activation(database, fixture, identity).await?;
    let prepared = prepared_instance(fixture, &activation, JobAuthorityProfile::Standard);
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            activation.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    let materialized = select_materialization(
        database,
        LogicalInstanceMaterializationTarget::new(
            TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.logical_job_id,
            prepared.activated.id(),
        )?,
        identity + 1,
    )
    .await?;
    let receipt = database
        .store()
        .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
            &materialized,
            &prepared.encoded,
            &prepared.envelope,
            &prepared.runtime_encoded,
            &prepared.runtime_context,
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    let session = open_runner(database, &fixture.tenant, identity + 2).await?;
    let terminal_completed_at = database_now_ms(database).await?;
    let result = JobResult::new(
        receipt.attempt_id(),
        JobConclusion::Failure,
        JobSecretExposure::ReadableSecret,
        UnixMillis::new(terminal_completed_at),
    )
    .with_outputs(BTreeMap::from([
        ("artifact".to_owned(), JobResultOutput::secret_derived()),
        ("masked".to_owned(), JobResultOutput::secret_derived()),
    ]));
    result.validate()?;
    let result_bytes = serde_json::to_vec(&result)?;
    seed_terminal_result(
        database,
        session,
        receipt.attempt_id(),
        &result_bytes,
        terminal_completed_at,
    )
    .await?;
    Ok((prepared, receipt.attempt_id()))
}

fn result_claim(
    target: LogicalInstanceResultTarget,
    owner: u128,
    observed_at: i64,
    expires_at: i64,
) -> ClaimLogicalInstanceResult {
    ClaimLogicalInstanceResult::new(
        target,
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(owner)).expect("worker"),
        UnixMillis::new(observed_at),
        UnixMillis::new(expires_at),
    )
    .expect("result claim")
}

fn expect_result_claimed(
    outcome: LogicalInstanceResultClaimOutcome,
) -> automata_ci_store::ClaimedLogicalInstanceResult {
    match outcome {
        LogicalInstanceResultClaimOutcome::Claimed(claimed) => claimed,
        other => panic!("expected result claim, got {other:?}"),
    }
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
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    JobId::from_uuid(Uuid::from_bytes(bytes))
}
