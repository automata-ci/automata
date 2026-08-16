use crate::github_manifest_fixture;
use crate::store::fixture::authenticated_github_idempotency;

use automata_ci_core::{
    CompiledValueTemplate, JobAuthorityProfile, JobConclusion, Located, LogicalJobKind,
    LogicalJobTemplate, LogicalRunStepTemplate, LogicalRunnerTemplate, LogicalStepKind,
    LogicalStepTemplate, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, RunId, Sha256Digest,
    StepJobTemplate, UnixMillis, WorkflowEventProvenance, WorkflowId, WorkflowJobKey, WorkflowPlan,
    WorkflowSourceProvenance, WorkflowStepKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AdmissionObject,
    AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation, ClaimLogicalJobResult,
    ClaimLogicalRunFinalization, ClaimNextLogicalJobOrchestration, ClaimProviderDelivery,
    ClaimedLogicalJobActivation, ClaimedLogicalRunFinalization, CommitLogicalJobResult,
    CommitLogicalRunFinalization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, EnsureGithubServerServiceAuthority,
    GithubCheckHeadSha, GithubCheckName, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision, GithubProviderOrigins,
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
    ProviderRepositoryVisibility, TenantScope, WorkflowAdmissionIdempotency, WorkflowConcurrency,
    WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::support::{TestDatabase, TestResult, run_with_database};

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

        // This test fixture changes already trusted result rows only to exercise
        // the run-level SQL precedence and transition mapping. The immutable
        // rejection trigger is disabled for the narrow update and restored
        // before finalization observes or claims any evidence.
        sqlx::query(
            "ALTER TABLE logical_workflow_job_results DISABLE TRIGGER logical_workflow_job_results_reject_update",
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
                UPDATE logical_workflow_job_results
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
                "UPDATE logical_workflow_jobs SET state = $2 WHERE id = $1",
            )
            .bind(fixture.job_ids[index].as_uuid())
            .bind(state)
            .execute(database.pool())
            .await?;
        }
        sqlx::query(
            "ALTER TABLE logical_workflow_job_results ENABLE TRIGGER logical_workflow_job_results_reject_update",
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
            FROM logical_workflow_runs AS marker
            JOIN logical_workflow_invocations AS invocation
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
            FROM logical_workflow_run_results AS result
            JOIN logical_workflow_runs AS marker ON marker.run_id = result.run_id
            JOIN logical_workflow_invocations AS invocation
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
        "SELECT count(*) FROM logical_workflow_run_result_claims WHERE run_id = $1",
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
        sqlx::query_scalar("SELECT count(*) FROM logical_workflow_run_results WHERE run_id = $1")
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
        sqlx::query_scalar("SELECT count(*) FROM logical_workflow_run_results WHERE run_id = $1")
            .bind(fixture.command.run_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(
        result_count, 0,
        "an expired fresh commit is side-effect free"
    );
    Ok(())
}

async fn admit_authenticated_fixture(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult<Uuid> {
    let configured_at = database_now_ms(database).await?;
    let bootstrap = github_manifest_fixture::fixture_github_repository_bootstrap(
        fixture.manifest.clone(),
        UnixMillis::new(configured_at),
    );
    database
        .store()
        .bootstrap_github_provider_repository(bootstrap.clone())
        .await?;
    crate::support::seed_fresh_github_workflow_permission_defaults(database, &bootstrap).await?;
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
    crate::support::register_provider_delivery_workflow_inventory(
        database,
        &fixture.manifest,
        &fixture.command,
        claimed.claim(),
        claimed.claimed_at(),
    )
    .await?;
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
            crate::support::authenticated_github_event_object(fixture.command.event())?,
            crate::support::provider_delivery_event_envelope(0x8e),
            UnixMillis::new(observed_at),
        )?,
        ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace)? + 1)?,
        ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace)? + 1)?,
        automata_ci_store::GithubAuthenticatedEvent::new(
            automata_ci_store::GithubAuthenticatedEventKind::Push,
            "refs/heads/main",
        )?,
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
        authenticated_github_idempotency(command)?,
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
    builder = builder.trust_snapshot(command.trust_snapshot().clone());
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
            concurrency_group_key, concurrency_queue_policy, runner_requirements_schema,
            event_digest, event_size_bytes, event_media_type, plan_digest,
            plan_object_key, plan_size_bytes, plan_media_type, plan_schema, workflow_name
        )
        SELECT $2, repository_id, workflow_id, snapshot_id, run_number + 1, 1,
               event_name, event_object_key, head_sha, 'queued', $3, $3,
               concurrency_group_key, concurrency_queue_policy, runner_requirements_schema,
               event_digest, event_size_bytes, event_media_type, plan_digest,
               plan_object_key, plan_size_bytes, plan_media_type, plan_schema, workflow_name
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
        INSERT INTO logical_workflow_concurrency_cancellations (
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
        JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
        JOIN logical_workflow_invocations AS invocation
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
        INSERT INTO logical_workflow_jobs (
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
        FROM logical_workflow_run_results AS result
        JOIN logical_workflow_runs AS marker ON marker.run_id = result.run_id
        JOIN logical_workflow_invocations AS invocation
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
            "UPDATE logical_workflow_run_results SET effective_conclusion = 'failure' WHERE run_id = $1",
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
        "SELECT EXISTS (SELECT 1 FROM logical_workflow_activation_preparations WHERE logical_job_id = $1)",
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
#[allow(clippy::too_many_lines)] // Builds the full authenticated admission graph.
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
    let repository = AdmissionRepository::new(
        manifest.repository_id(),
        "github",
        namespace.to_string(),
        "example",
        format!("project-{namespace}"),
    )
    .expect("repository");
    let head_sha = vec![0x14; 20];
    let trust_snapshot = crate::support::authenticated_github_trust_snapshot(
        &repository,
        "refs/heads/main",
        &head_sha,
    )
    .expect("trust snapshot");
    let mut command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!("run-finalization-{namespace}"))
            .expect("idempotency"),
        Sha256Digest::from_bytes([0x40; 32]),
        repository,
        workflow_id,
        ".ci/workflows/ci.yml",
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
        head_sha,
        logical_jobs,
        UnixMillis::new(1_000),
    )
    .trust_snapshot(trust_snapshot);
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
