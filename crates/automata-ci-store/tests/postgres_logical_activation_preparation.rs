#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use automata_ci_core::{
    CompiledValueTemplate, ContextValue, JobAuthorityProfile, JobConclusion, JobContentReference,
    JobExecutionContext, JobInstanceIdentity, JobIr, JobIrEnvelope, JobPermissionRequest,
    JobRuntimeContext, JobSource, Located, LogicalJobKind, LogicalJobTemplate,
    LogicalRunStepTemplate, LogicalRunnerTemplate, LogicalStepKind, LogicalStepTemplate,
    PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, RunId, RunValueTemplates,
    RunnerRequirements, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    StrategyContext, UnixMillis, ValueTemplate, WorkflowEventProvenance, WorkflowId,
    WorkflowJobKey, WorkflowPlan, WorkflowSourceProvenance, WorkflowStepKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation, ClaimLogicalJobResult,
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ClaimProviderDelivery, ClaimedLogicalActivationPreparation, ClaimedLogicalJobActivation,
    CommitLogicalInstanceMaterialization, CommitLogicalJobResult,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, EnsureGithubServerServiceAuthority,
    GithubCheckHeadSha, GithubCheckName, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    JobEnvironmentActivationEvidence, JobEventTrust, JobSourceKind, LogicalActivationObject,
    LogicalActivationPreparationStore as _, LogicalActivationPreparationStoreError,
    LogicalActivationPreparationTarget, LogicalActivationRepository as _,
    LogicalActivationWorkerId, LogicalInstanceMaterializationSelectionOutcome,
    LogicalJobOrchestrationSelectionOutcome, LogicalJobResultClaimOutcome,
    LogicalJobResultRepository as _, LogicalJobResultTarget, LogicalJobResultWorkerId,
    LogicalMaterializationRepository as _, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    LogicalWorkSelectionRepository as _, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowAdmissionStoreError, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, PublishLogicalJobActivation, RenewLogicalActivationPreparation,
    ReusableSecretPermission, TenantScope, WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

struct Fixture {
    tenant: String,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    first: LogicalWorkflowJobId,
    second: LogicalWorkflowJobId,
    historical: LogicalWorkflowJobId,
    plan: WorkflowPlan,
    plan_bytes: Vec<u8>,
}

struct PreparedMaterialization {
    activated: ActivatedLogicalInstanceDescriptor,
    envelope: JobIrEnvelope,
    encoded: Vec<u8>,
    runtime_context: JobRuntimeContext,
    runtime_encoded: Vec<u8>,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn preparation_is_dependency_ready_fenced_replayable_and_workspace_bound() -> TestResult {
    run_with_database(|database| async move {
        let canonical_windows: bool = sqlx::query_scalar(
            r"SELECT automata_is_canonical_logical_activation_workspace(E'C:\\runner\\work')",
        )
        .fetch_one(database.pool())
        .await?;
        let traversing_windows: bool = sqlx::query_scalar(
            r"SELECT automata_is_canonical_logical_activation_workspace(E'C:\\runner\\..\\work')",
        )
        .fetch_one(database.pool())
        .await?;
        let mixed_windows: bool = sqlx::query_scalar(
            r"SELECT automata_is_canonical_logical_activation_workspace(E'C:\\runner/../work')",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(canonical_windows);
        assert!(!traversing_windows);
        assert!(!mixed_windows);

        let fixture = fixture(
            &database,
            "activation-preparation-live",
            130_000,
            JobAuthorityProfile::Standard,
        )
        .await?;

        let first =
            claim_preparation(&database, &fixture, fixture.first, 130_100, 1_010, 1_100).await?;
        assert_eq!(
            first.descriptor().authority_profile(),
            JobAuthorityProfile::Standard
        );
        let first_receipt = bind_preparation(&database, &first, 1_020, "first").await?;
        let historical_reservation =
            claim_preparation(&database, &fixture, fixture.historical, 130_099, 0, 0).await?;
        let first_activation =
            select_activation(&database, &fixture, fixture.first, 130_101, 230_101).await?;
        assert_eq!(
            first_activation.claim().input_digest(),
            first_receipt.input_digest()
        );
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                first_activation.claim().clone(),
                false,
                Vec::new(),
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        let rotated = rotated_manifest(&fixture.manifest, JobAuthorityProfile::CredentialFree);
        database
            .store()
            .bootstrap_github_provider_repository(
                github_manifest_fixture::fixture_github_repository_bootstrap(
                    rotated,
                    UnixMillis::new(database_now_ms(&database).await?),
                ),
            )
            .await?;

        let current = database
            .store()
            .load_current_github_provider_manifest(
                fixture.manifest.tenant(),
                fixture.manifest.connection_id(),
            )
            .await?;
        assert_eq!(
            current.manifest().authority_profile(),
            JobAuthorityProfile::CredentialFree
        );
        wait_until_database_after(&database, historical_reservation.claim().expires_at().get())
            .await?;
        let historical = claim_preparation(
            &database,
            &fixture,
            fixture.historical,
            130_110,
            1_050,
            1_140,
        )
        .await?;
        assert_eq!(
            historical.descriptor().authority_profile(),
            JobAuthorityProfile::Standard,
            "a newly prepared historical run must not consult the rotated current manifest"
        );
        let historical_receipt =
            bind_preparation(&database, &historical, 1_060, "historical").await?;
        let historical_activation =
            select_activation(&database, &fixture, fixture.historical, 130_111, 230_111).await?;
        assert_eq!(
            historical_activation.claim().input_digest(),
            historical_receipt.input_digest()
        );
        let historical_instance = prepared_materialization(
            &fixture,
            &historical_activation,
            JobAuthorityProfile::Standard,
            "/runner/work/historical",
            "historical",
        );
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                historical_activation.claim().clone(),
                true,
                vec![historical_instance.activated.clone()],
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        let historical_materialization = select_materialization(
            &database,
            &fixture,
            fixture.historical,
            historical_instance.activated.id(),
            130_112,
            230_112,
        )
        .await?;
        database
            .store()
            .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
                &historical_materialization,
                &historical_instance.encoded,
                &historical_instance.envelope,
                &historical_instance.runtime_encoded,
                &historical_instance.runtime_context,
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        let historical_profiles: (String, String, String, String, String, String) = sqlx::query_as(
            r"
                SELECT job.authority_profile, claim.authority_profile,
                       preparation.authority_profile, publication.authority_profile,
                       materialization.authority_profile, concrete.authority_profile
                FROM logical_workflow_jobs AS job
                JOIN logical_workflow_activation_preparation_claims AS claim
                  ON claim.logical_job_id = job.id
                JOIN logical_workflow_activation_preparations AS preparation
                  ON preparation.logical_job_id = job.id
                JOIN logical_workflow_activation_publications AS publication
                  ON publication.logical_job_id = job.id
                JOIN logical_workflow_materialization_claims AS materialization
                  ON materialization.logical_job_id = job.id
                JOIN logical_workflow_concrete_jobs AS concrete
                  ON concrete.logical_job_id = job.id
                WHERE job.id = $1
                ",
        )
        .bind(fixture.historical.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            historical_profiles,
            (
                "standard".to_owned(),
                "standard".to_owned(),
                "standard".to_owned(),
                "standard".to_owned(),
                "standard".to_owned(),
                "standard".to_owned(),
            )
        );

        let blocked_at = database_now_ms(&database).await?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
                    LogicalWorkSelectionId::from_uuid(Uuid::from_u128(230_102))?,
                    worker(130_102),
                    UnixMillis::new(blocked_at),
                    60_000,
                )?)
                .await?,
            LogicalJobOrchestrationSelectionOutcome::Idle
        ));

        let result_time: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(database.pool())
        .await?;

        let result_target = LogicalJobResultTarget::new(
            tenant(&fixture)?,
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.first,
        )?;
        let result_claim = match database
            .store()
            .claim_logical_job_result(ClaimLogicalJobResult::new(
                result_target,
                LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(130_102))?,
                UnixMillis::new(result_time),
                UnixMillis::new(result_time + 60_000),
            )?)
            .await?
        {
            LogicalJobResultClaimOutcome::Claimed(claimed) => claimed,
            outcome => panic!("expected job-result claim, got {outcome:?}"),
        };
        let commit = CommitLogicalJobResult::new(
            &result_claim,
            &fixture.plan_bytes,
            &fixture.plan,
            UnixMillis::new(database_now_ms(&database).await?),
        )?;
        assert_eq!(commit.effective_conclusion(), JobConclusion::Skipped);
        database.store().commit_logical_job_result(commit).await?;

        let selection_at = database_now_ms(&database).await?;
        let left = ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(230_104))?,
            worker(130_104),
            UnixMillis::new(selection_at),
            2_000,
        )?;
        let right = ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(230_105))?,
            worker(130_105),
            UnixMillis::new(selection_at),
            2_000,
        )?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left_outcome, right_outcome) = tokio::join!(
            left_store.claim_next_logical_job_orchestration(left.clone()),
            right_store.claim_next_logical_job_orchestration(right.clone()),
        );
        let (selected, winning_request) = match (left_outcome?, right_outcome?) {
            (
                LogicalJobOrchestrationSelectionOutcome::Selected(selected),
                LogicalJobOrchestrationSelectionOutcome::Idle
                | LogicalJobOrchestrationSelectionOutcome::Contended,
            ) => (selected, left),
            (
                LogicalJobOrchestrationSelectionOutcome::Idle
                | LogicalJobOrchestrationSelectionOutcome::Contended,
                LogicalJobOrchestrationSelectionOutcome::Selected(selected),
            ) => (selected, right),
            outcomes => panic!("exactly one preparation claim must win: {outcomes:?}"),
        };
        let consumed = database
            .store()
            .consume_selected_logical_job_orchestration(
                ConsumeSelectedLogicalJobOrchestration::new(selected.clone()),
            )
            .await?;
        let winner = match consumed.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed.clone(),
            authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
                panic!("expected preparation authority, got {authority:?}")
            }
        };
        assert_eq!(
            winner.descriptor().status(),
            automata_ci_store::LogicalActivationAggregateStatus::Skipped
        );
        assert_eq!(winner.descriptor().prerequisites().len(), 1);
        assert_eq!(
            winner.descriptor().authority_profile(),
            JobAuthorityProfile::Standard,
            "historical activation must retain the admitted manifest profile after rotation"
        );
        assert_eq!(
            winner.descriptor().prerequisites()[0].effective_conclusion(),
            JobConclusion::Skipped
        );
        let replayed_selection = match database
            .store()
            .claim_next_logical_job_orchestration(winning_request.clone())
            .await?
        {
            LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
            outcome => panic!("expected exact preparation replay, got {outcome:?}"),
        };
        assert_eq!(replayed_selection, selected);
        let replayed = database
            .store()
            .consume_selected_logical_job_orchestration(
                ConsumeSelectedLogicalJobOrchestration::new(replayed_selection),
            )
            .await?;
        let replay = match replayed.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
            authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
                panic!("expected preparation replay, got {authority:?}")
            }
        };
        assert!(replay.is_replay());
        assert_eq!(replay.claim(), winner.claim());

        let stale = BindLogicalActivationPreparation::new(
            winner.descriptor().clone(),
            winner.claim().clone(),
            winner.descriptor().base_context().clone(),
            context_object("stale/needs.pb", 51),
            winner.claim().claimed_at(),
        )?;
        let renewal = RenewLogicalActivationPreparation::new(winner.claim().clone(), 2_000)?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left_renewal, right_renewal) = tokio::join!(
            left_store.renew_logical_activation_preparation(renewal.clone()),
            right_store.renew_logical_activation_preparation(renewal),
        );
        let left_renewal = left_renewal?;
        let right_renewal = right_renewal?;
        assert_eq!(left_renewal, right_renewal);
        assert_eq!(left_renewal.predecessor(), winner.claim());
        assert_eq!(left_renewal.successor_generation().get(), 2);
        let current_selection = match database
            .store()
            .claim_next_logical_job_orchestration(winning_request)
            .await?
        {
            LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
            outcome => panic!("expected current-successor selection replay, got {outcome:?}"),
        };
        assert_eq!(current_selection, selected);
        let current = database
            .store()
            .consume_selected_logical_job_orchestration(
                ConsumeSelectedLogicalJobOrchestration::new(current_selection),
            )
            .await?;
        let current = match current.authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
            authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
                panic!("expected current preparation successor, got {authority:?}")
            }
        };
        assert_eq!(
            current.claim().generation(),
            left_renewal.successor_generation()
        );
        assert_eq!(
            current.claim().claimed_at(),
            left_renewal.successor_claimed_at()
        );
        assert_eq!(
            current.claim().expires_at(),
            left_renewal.successor_expires_at()
        );
        wait_until_database_after(&database, current.claim().expires_at().get()).await?;
        let takeover_selected = select_orchestration_preparation(
            &database,
            &fixture,
            fixture.second,
            130_107,
            230_107,
            60_000,
        )
        .await?;
        let takeover = takeover_selected;
        assert_eq!(takeover.claim().generation().get(), 3);
        assert!(matches!(
            database
                .store()
                .bind_logical_activation_preparation(stale)
                .await,
            Err(LogicalActivationPreparationStoreError::ClaimRejected)
        ));
        let second_receipt =
            bind_preparation(&database, &takeover, result_time + 160, "second").await?;
        let changed_binding = BindLogicalActivationPreparation::new(
            takeover.descriptor().clone(),
            takeover.claim().clone(),
            takeover.descriptor().base_context().clone(),
            context_object("contexts/changed/needs.pb", 60),
            second_receipt.bound_at(),
        )?;
        assert!(matches!(
            database
                .store()
                .bind_logical_activation_preparation(changed_binding)
                .await,
            Err(LogicalActivationPreparationStoreError::BindConflict)
        ));

        let second_activation =
            select_activation(&database, &fixture, fixture.second, 130_109, 230_109).await?;
        assert_eq!(
            second_activation.claim().input_digest(),
            second_receipt.input_digest()
        );
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                second_activation.claim().clone(),
                false,
                Vec::new(),
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn credential_free_profile_is_exactly_pinned_and_opposite_substitution_is_rejected()
-> TestResult {
    run_with_database(|database| async move {
        let fixture = fixture_with_visibility(
            &database,
            "activation-preparation-credential-free",
            131_000,
            JobAuthorityProfile::CredentialFree,
            ProviderRepositoryVisibility::Private,
        )
        .await?;
        assert_eq!(
            fixture.manifest.repository_visibility(),
            ProviderRepositoryVisibility::Private
        );
        let private_delivery_bound: bool = sqlx::query_scalar(
            "SELECT repository_visibility = 'private' \
                    AND private_source_authority_id IS NOT NULL \
             FROM github_provider_delivery_evidence \
             WHERE tenant_id = $1 AND repository_id = $2",
        )
        .bind(&fixture.tenant)
        .bind(fixture.manifest.repository_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(private_delivery_bound);
        let claimed =
            claim_preparation(&database, &fixture, fixture.first, 131_100, 1_010, 1_100).await?;
        let _historical_reservation =
            claim_preparation(&database, &fixture, fixture.historical, 131_099, 0, 0).await?;
        assert_eq!(
            claimed.descriptor().authority_profile(),
            JobAuthorityProfile::CredentialFree
        );

        let substitution = sqlx::query(
            "UPDATE logical_workflow_activation_preparation_claims \
             SET authority_profile = 'standard' WHERE logical_job_id = $1",
        )
        .bind(fixture.first.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("an opposite-profile substitution must be rejected");
        assert!(
            substitution
                .as_database_error()
                .is_some_and(|error| error.code().as_deref() == Some("23514"))
        );

        let receipt = bind_preparation(&database, &claimed, 1_020, "credential-free").await?;
        let activation =
            select_activation(&database, &fixture, fixture.first, 131_101, 231_101).await?;
        assert_eq!(activation.claim().input_digest(), receipt.input_digest());
        let prepared_instance = prepared_materialization(
            &fixture,
            &activation,
            JobAuthorityProfile::CredentialFree,
            "/runner/work/credential-free",
            "credential-free",
        );
        database
            .store()
            .publish_logical_job_activation(PublishLogicalJobActivation::new(
                activation.claim().clone(),
                true,
                vec![prepared_instance.activated.clone()],
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;
        let materialization = select_materialization(
            &database,
            &fixture,
            fixture.first,
            prepared_instance.activated.id(),
            131_102,
            231_102,
        )
        .await?;
        database
            .store()
            .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
                &materialization,
                &prepared_instance.encoded,
                &prepared_instance.envelope,
                &prepared_instance.runtime_encoded,
                &prepared_instance.runtime_context,
                UnixMillis::new(database_now_ms(&database).await?),
            )?)
            .await?;

        let profiles: (String, String, String, String, String, String) = sqlx::query_as(
            r"
            SELECT job.authority_profile, claim.authority_profile,
                   preparation.authority_profile, publication.authority_profile,
                   materialization.authority_profile, concrete.authority_profile
            FROM logical_workflow_jobs AS job
            JOIN logical_workflow_activation_preparation_claims AS claim
              ON claim.logical_job_id = job.id
            JOIN logical_workflow_activation_preparations AS preparation
              ON preparation.logical_job_id = job.id
            JOIN logical_workflow_activation_publications AS publication
              ON publication.logical_job_id = job.id
            JOIN logical_workflow_materialization_claims AS materialization
              ON materialization.logical_job_id = job.id
            JOIN logical_workflow_concrete_jobs AS concrete
              ON concrete.logical_job_id = job.id
            WHERE job.id = $1
            ",
        )
        .bind(fixture.first.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            profiles,
            (
                "credential_free".to_owned(),
                "credential_free".to_owned(),
                "credential_free".to_owned(),
                "credential_free".to_owned(),
                "credential_free".to_owned(),
                "credential_free".to_owned(),
            )
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn github_shaped_admission_without_historical_provider_evidence_has_no_profile_fallback()
-> TestResult {
    run_with_database(|database| async move {
        let tenant = "activation-preparation-no-fallback";
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) \
             VALUES ($1, 'No fallback', 1, 1)",
        )
        .bind(tenant)
        .execute(database.pool())
        .await?;

        let namespace = 132_000_u128;
        let tenant_scope = TenantScope::from_authenticated_tenant_id(tenant)?;
        let run = RunId::from_uuid(Uuid::from_u128(namespace + 4));
        let invocation = LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5))?;
        let job = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6))?;
        let plan = workflow_plan();
        let plan_bytes = serde_json::to_vec(&plan)?;
        let command = AdmitLogicalWorkflowRun::builder(
            tenant_scope.clone(),
            WorkflowAdmissionIdempotency::provider_delivery("github-shaped-no-evidence")?,
            Sha256Digest::from_bytes([81; 32]),
            AdmissionRepository::new(
                automata_ci_store::RepositoryId::from_uuid(Uuid::from_u128(namespace + 1)),
                "github",
                "999999",
                "automata-ci",
                "missing-evidence",
            )?,
            WorkflowId::from_uuid(Uuid::from_u128(namespace + 2)),
            ".ci/workflows/ci.yml",
            "Automata CI",
            "refs/heads/main",
            WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3)),
            object(
                format!("preparation/{namespace}/source"),
                &[1; 64],
                "application/json",
            ),
            object(
                format!("preparation/{namespace}/plan.json"),
                &plan_bytes,
                "application/vnd.automata.workflow-plan+json",
            ),
            run,
            1,
            invocation,
            "push",
            object(
                format!("preparation/{namespace}/event"),
                &[2; 64],
                "application/json",
            ),
            vec![3; 20],
            vec![AdmittedLogicalWorkflowJob::new(
                job,
                WorkflowJobKey::new("first")?,
                0,
                LogicalWorkflowJobKind::Steps,
                Vec::new(),
            )?],
            UnixMillis::new(database_now_ms(&database).await?),
        )
        .build()?;
        assert!(matches!(
            database.store().admit_logical_workflow(command).await,
            Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
        ));
        let inserted: i64 = sqlx::query_scalar("SELECT count(*) FROM workflow_runs WHERE id = $1")
            .bind(run.as_uuid())
            .fetch_one(database.pool())
            .await?;
        assert_eq!(inserted, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn selector_quarantines_expired_max_generation_and_advances_to_newer_work() -> TestResult {
    run_with_database(|database| async move {
        let fixture = fixture(
            &database,
            "activation-preparation-generation-poison",
            133_000,
            JobAuthorityProfile::Standard,
        )
        .await?;
        let poisoned = claim_preparation(&database, &fixture, fixture.first, 133_100, 0, 0).await?;
        let reserved_historical = select_orchestration_preparation(
            &database,
            &fixture,
            fixture.historical,
            133_099,
            233_099,
            60_000,
        )
        .await?;
        assert_eq!(
            reserved_historical.claim().target().logical_job_id(),
            fixture.historical
        );
        wait_until_database_after(&database, poisoned.claim().claimed_at().get() + 10).await?;
        let expired_at = database_now_ms(&database).await? - 1;
        let mut corruption = database.pool().begin().await?;
        sqlx::query(
            "ALTER TABLE logical_workflow_activation_preparation_claims DISABLE TRIGGER USER",
        )
        .execute(&mut *corruption)
        .await?;
        let updated = sqlx::query(
            r"
            UPDATE logical_workflow_activation_preparation_claims
            SET generation = 9223372036854775807,
                expires_at_ms = $2, updated_at_ms = $2
            WHERE logical_job_id = $1 AND state = 'preparing'
            ",
        )
        .bind(fixture.first.as_uuid())
        .bind(expired_at)
        .execute(&mut *corruption)
        .await?;
        assert_eq!(updated.rows_affected(), 1);
        sqlx::query(
            "ALTER TABLE logical_workflow_activation_preparation_claims ENABLE TRIGGER USER",
        )
        .execute(&mut *corruption)
        .await?;
        corruption.commit().await?;

        let observed_at = database_now_ms(&database).await?;
        let poison_request = ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(233_100))?,
            worker(133_101),
            UnixMillis::new(observed_at),
            60_000,
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_orchestration(poison_request.clone())
                .await?,
            LogicalJobOrchestrationSelectionOutcome::Quarantined
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_orchestration(poison_request)
                .await?,
            LogicalJobOrchestrationSelectionOutcome::Quarantined
        ));
        let quarantine: (i64, String) = sqlx::query_as(
            r"
            SELECT authority_generation, failure_kind
            FROM logical_workflow_activation_work_quarantines
            WHERE logical_job_id = $1
            ",
        )
        .bind(fixture.first.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(quarantine, (i64::MAX, "generation_exhausted".to_owned()));

        let newer = fixture_with_visibility(
            &database,
            "activation-preparation-after-generation-poison",
            133_500,
            JobAuthorityProfile::Standard,
            ProviderRepositoryVisibility::Public,
        )
        .await?;
        let next = claim_preparation(&database, &newer, newer.first, 133_501, 0, 0).await?;
        assert_eq!(next.claim().target().logical_job_id(), newer.first);
        assert_eq!(next.claim().generation().get(), 1);
        Ok(())
    })
    .await
}

#[allow(clippy::too_many_lines)] // The fixture supplies the complete immutable materialization descriptor.
fn prepared_materialization(
    fixture: &Fixture,
    claimed: &ClaimedLogicalJobActivation,
    authority_profile: JobAuthorityProfile,
    workspace: &str,
    object_namespace: &str,
) -> PreparedMaterialization {
    let matrix_digest = Sha256Digest::from_bytes([0x77; 32]);
    let identity = JobInstanceIdentity::new(claimed.logical_key().as_str(), 0, 1, matrix_digest)
        .expect("matrix identity");
    let empty = ContextValue::empty_object();
    let runtime_context = JobRuntimeContext::new(
        empty.clone(),
        empty.clone(),
        empty,
        StrategyContext::new(false, 0, 1, 1).expect("strategy"),
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
    )
    .expect("runtime context");
    let runtime_encoded = serde_json::to_vec(&runtime_context).expect("encoded runtime context");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes(Sha256::digest(&runtime_encoded).into()),
        ObjectKey::new(format!("contexts/{object_namespace}.pb")).expect("runtime key"),
        u64::try_from(runtime_encoded.len()).expect("runtime size"),
    )
    .expect("runtime descriptor");
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
        deterministic_job_id(
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            claimed.claim().logical_job_id(),
            matrix_digest,
        ),
        fixture.command.run_id(),
        "Credential-free build",
        RunnerRequirements::default(),
        identity.clone(),
        false,
        vec![step],
    )
    .with_authority_profile(authority_profile);
    let job = if authority_profile == JobAuthorityProfile::CredentialFree {
        job.with_permission_request(JobPermissionRequest::mapping([]))
    } else {
        job
    };
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
            ".ci/workflows/ci.yml",
            "push",
        ),
        job_execution,
        job,
    );
    envelope.validate().expect("profiled JobIR");
    let encoded = serde_json::to_vec(&envelope).expect("encoded JobIR");
    let activated = ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        workspace.to_owned(),
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new(format!("job-ir/{object_namespace}.pb")).expect("JobIR key"),
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
    PreparedMaterialization {
        activated,
        envelope,
        encoded,
        runtime_context,
        runtime_encoded,
    }
}

fn deterministic_job_id(
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    matrix_digest: Sha256Digest,
) -> automata_ci_core::JobId {
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
    automata_ci_core::JobId::from_uuid(Uuid::from_bytes(bytes))
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

async fn claim_preparation(
    database: &TestDatabase,
    fixture: &Fixture,
    job: LogicalWorkflowJobId,
    owner: u128,
    _observed: i64,
    _expires: i64,
) -> TestResult<ClaimedLogicalActivationPreparation> {
    select_orchestration_preparation(database, fixture, job, owner, owner + 1_000_000, 2_000).await
}

async fn select_orchestration_preparation(
    database: &TestDatabase,
    fixture: &Fixture,
    job: LogicalWorkflowJobId,
    owner: u128,
    selection: u128,
    duration_ms: i64,
) -> TestResult<ClaimedLogicalActivationPreparation> {
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection))?,
            worker(owner),
            UnixMillis::new(observed_at),
            duration_ms,
        )?)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected preparation selection, got {outcome:?}").into()),
    };
    let expected = LogicalActivationPreparationTarget::new(
        tenant(fixture)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        job,
    )?;
    assert_eq!(selected.target(), &expected);
    let consumed = database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?;
    match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => Ok(claimed.clone()),
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            Err(format!("expected preparation authority, got {authority:?}").into())
        }
    }
}

async fn bind_preparation(
    database: &TestDatabase,
    claimed: &ClaimedLogicalActivationPreparation,
    _bound_at: i64,
    namespace: &str,
) -> TestResult<automata_ci_store::LogicalActivationPreparationReceipt> {
    let request = BindLogicalActivationPreparation::new(
        claimed.descriptor().clone(),
        claimed.claim().clone(),
        claimed.descriptor().base_context().clone(),
        context_object(&format!("contexts/{namespace}/needs.pb"), 42),
        UnixMillis::new(database_now_ms(database).await?),
    )?;
    let left = database
        .store()
        .bind_logical_activation_preparation(request)
        .await?;
    assert!(!left.is_replay());
    Ok(left)
}

async fn select_activation(
    database: &TestDatabase,
    fixture: &Fixture,
    job: LogicalWorkflowJobId,
    owner: u128,
    selection: u128,
) -> TestResult<ClaimedLogicalJobActivation> {
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection))?,
            worker(owner),
            UnixMillis::new(observed_at),
            60_000,
        )?)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected activation selection, got {outcome:?}").into()),
    };
    assert_eq!(selected.target().run_id(), fixture.command.run_id());
    assert_eq!(selected.target().logical_job_id(), job);
    let consumed = database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?;
    match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => Ok(claimed.clone()),
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            Err(format!("expected activation authority, got {authority:?}").into())
        }
    }
}

async fn select_materialization(
    database: &TestDatabase,
    fixture: &Fixture,
    job: LogicalWorkflowJobId,
    instance: automata_ci_store::LogicalWorkflowInstanceId,
    owner: u128,
    selection: u128,
) -> TestResult<automata_ci_store::ClaimedLogicalInstanceMaterialization> {
    let observed_at = database_now_ms(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_instance_materialization(ClaimNextLogicalInstanceMaterialization::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection))?,
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
    assert_eq!(selected.target().run_id(), fixture.command.run_id());
    assert_eq!(selected.target().logical_job_id(), job);
    assert_eq!(selected.target().instance_id(), instance);
    Ok(database
        .store()
        .consume_selected_logical_instance_materialization(
            ConsumeSelectedLogicalInstanceMaterialization::new(selected),
        )
        .await?
        .authority()
        .clone())
}

fn tenant(fixture: &Fixture) -> TestResult<TenantScope> {
    Ok(TenantScope::from_authenticated_tenant_id(&fixture.tenant)?)
}

fn worker(value: u128) -> LogicalActivationWorkerId {
    LogicalActivationWorkerId::from_uuid(Uuid::from_u128(value)).expect("worker")
}

fn context_object(key: &str, digest: u8) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("context key"),
        128,
        "application/vnd.automata.job-runtime-context.protobuf",
    )
    .expect("context object")
}

async fn fixture(
    database: &TestDatabase,
    tenant: &str,
    namespace: u128,
    authority_profile: JobAuthorityProfile,
) -> TestResult<Fixture> {
    fixture_with_visibility(
        database,
        tenant,
        namespace,
        authority_profile,
        ProviderRepositoryVisibility::Public,
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn fixture_with_visibility(
    database: &TestDatabase,
    tenant: &str,
    namespace: u128,
    authority_profile: JobAuthorityProfile,
    visibility: ProviderRepositoryVisibility,
) -> TestResult<Fixture> {
    let tenant_scope = TenantScope::from_authenticated_tenant_id(tenant)?;
    let configured_at = database_now_ms(database).await?;
    let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 20))?;
    let installation = ProviderInstallationId::new(101)?;
    let github_repository = ProviderRepositoryId::new(202)?;
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new(
        tenant_scope.clone(),
        connection,
        installation,
        github_repository,
        GithubRepositoryName::new("automata-ci/automata")?,
        visibility,
        GithubServerServiceAppId::new(303)?,
        GithubServerServiceAppClientId::new("Iv1.activation-profile")?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([7; 32]),
        GithubServerServiceRevision::new(1)?,
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([6; 32]))?,
        GithubServerServiceRevision::new(1)?,
        GithubServerServiceRevision::new(1)?,
        authority_profile,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI")?,
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1)?,
    );
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                UnixMillis::new(configured_at),
            ),
        )
        .await?;
    let checks = GithubServerServiceAuthorityIdentity::new(
        tenant_scope.clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(namespace + 21))?,
        manifest.repository_id(),
        connection,
        installation,
        manifest.github_app_id(),
        github_repository,
        manifest.github_repository_name().clone(),
        GithubServerServiceScope::ChecksWrite,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
        Sha256Digest::from_bytes([11; 32]),
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            checks,
            UnixMillis::new(configured_at),
        )?)
        .await?;
    if visibility == ProviderRepositoryVisibility::Private {
        let private_source = GithubServerServiceAuthorityIdentity::new(
            tenant_scope.clone(),
            GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(namespace + 23))?,
            manifest.repository_id(),
            connection,
            installation,
            manifest.github_app_id(),
            github_repository,
            manifest.github_repository_name().clone(),
            GithubServerServiceScope::PrivateRepositorySourceRead,
            manifest.app_client_id().clone(),
            manifest.jwt_issuer(),
            manifest.app_key_spki_sha256(),
            manifest.app_configuration_revision(),
            manifest.policy_revision(),
            Sha256Digest::from_bytes([12; 32]),
        )?;
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                private_source,
                UnixMillis::new(configured_at),
            )?)
            .await?;
    }

    let workflow = WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5)).expect("invocation");
    let first = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("first");
    let second = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 7)).expect("second");
    let historical =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 8)).expect("historical");
    let plan = workflow_plan();
    let plan_bytes = serde_json::to_vec(&plan).expect("canonical plan");
    let jobs = vec![
        AdmittedLogicalWorkflowJob::new(
            first,
            WorkflowJobKey::new("first").expect("key"),
            0,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        )
        .expect("first job"),
        AdmittedLogicalWorkflowJob::new(
            second,
            WorkflowJobKey::new("second").expect("key"),
            1,
            LogicalWorkflowJobKind::Steps,
            vec![first],
        )
        .expect("second job"),
        AdmittedLogicalWorkflowJob::new(
            historical,
            WorkflowJobKey::new("historical").expect("key"),
            2,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        )
        .expect("historical job"),
    ];
    let event = object(
        format!("preparation/{namespace}/event"),
        &[2; 64],
        "application/json",
    );
    let mut command = AdmitLogicalWorkflowRun::builder(
        tenant_scope.clone(),
        WorkflowAdmissionIdempotency::provider_delivery(format!("preparation-{namespace}"))
            .expect("idempotency"),
        Sha256Digest::from_bytes([30; 32]),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            github_repository.get().to_string(),
            "automata-ci",
            "automata",
        )
        .expect("repository"),
        workflow,
        ".ci/workflows/ci.yml",
        "Automata CI",
        "refs/heads/main",
        snapshot,
        object(
            format!("preparation/{namespace}/source"),
            &[1; 64],
            "application/json",
        ),
        object(
            format!("preparation/{namespace}/plan.json"),
            &plan_bytes,
            "application/vnd.automata.workflow-plan+json",
        ),
        run,
        1,
        invocation,
        "push",
        event.clone(),
        vec![3; 20],
        jobs,
        UnixMillis::new(configured_at),
    )
    .base_context(object(
        format!("preparation/{namespace}/base-context.pb"),
        &[4; 64],
        "application/vnd.automata.job-runtime-context.protobuf",
    ))
    .build()
    .expect("admission");
    let accepted = database
        .store()
        .accept_manifest_pinned_github_delivery(AcceptManifestPinnedGithubDelivery::new(
            AcceptProviderDelivery::new(
                ProviderDeliveryIdentity::new(
                    tenant_scope.clone(),
                    "github",
                    connection,
                    installation,
                    ProviderRepositoryCoordinates::new(
                        github_repository,
                        visibility,
                        "automata-ci/automata",
                    )?,
                    format!("activation-preparation-{namespace}"),
                )?,
                Sha256Digest::from_bytes([29; 32]),
                event,
                UnixMillis::new(database_now_ms(database).await?),
            )?,
            ProviderRepositoryOwnerId::new(404)?,
            ProviderRepositoryOwnerId::new(404)?,
            automata_ci_store::GithubAuthenticatedEvent::new(
                automata_ci_store::GithubAuthenticatedEventKind::Push,
                "refs/heads/main",
            )?,
            GithubCheckHeadSha::new([3; 20])?,
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
    command = logical_command_at(&command, claimed.claimed_at())?;
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
    Ok(Fixture {
        tenant: tenant.to_owned(),
        manifest,
        command,
        first,
        second,
        historical,
        plan,
        plan_bytes,
    })
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

fn rotated_manifest(
    prior: &GithubProviderManifest,
    authority_profile: JobAuthorityProfile,
) -> GithubProviderManifest {
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
            .expect("rotated policy revision"),
        authority_profile,
        prior.runner_policy().clone(),
        prior.runtime_policy_revision(),
        prior.runtime_policy_digest(),
        prior.check_name().clone(),
        prior.origins(),
        prior.limits(),
        GithubProviderManifestRevision::new(prior.revision().get() + 1)
            .expect("rotated manifest revision"),
    )
}

fn object(key: String, bytes: &[u8], media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        ObjectKey::new(key).expect("object key"),
        u64::try_from(bytes.len()).expect("size"),
        media_type,
    )
    .expect("object")
}

fn workflow_plan() -> WorkflowPlan {
    let first = logical_job("first", 0, Vec::new());
    let second = logical_job(
        "second",
        1,
        vec![located(WorkflowJobKey::new("first").expect("need"))],
    );
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "forge",
            "current.yml",
            PlanSourceOrigin::Memory {
                name: "current.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("forge", "push"),
        vec![first, second],
        span(),
    )
    .build()
    .expect("plan")
}

fn logical_job(
    key: &str,
    source_order: u32,
    needs: Vec<Located<WorkflowJobKey>>,
) -> LogicalJobTemplate {
    let runner = LogicalRunnerTemplate::new(
        None,
        vec![located(CompiledValueTemplate::Literal("linux".to_owned()))],
        span(),
    );
    let step = LogicalStepTemplate::builder(
        located(WorkflowStepKey::new(format!("position/{source_order:08}")).expect("step key")),
        LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
            located(CompiledValueTemplate::Literal("true".to_owned())),
            None,
            None,
        ))),
        span(),
    )
    .build()
    .expect("step");
    LogicalJobTemplate::builder(
        located(WorkflowJobKey::new(key).expect("job key")),
        source_order,
        LogicalJobKind::Steps(automata_ci_core::StepJobTemplate::new(
            runner,
            vec![step],
            span(),
        )),
        span(),
    )
    .needs(needs)
    .build()
    .expect("job")
}

fn span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "current.yml",
        PlanSourceLocation::new(0, 1, 1).expect("start"),
        PlanSourceLocation::new(1, 1, 2).expect("end"),
    )
    .expect("span")
}

fn located<T>(value: T) -> Located<T> {
    Located::new(value, span())
}
