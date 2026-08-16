use crate::github_manifest_fixture;

use std::collections::BTreeMap;

use automata_ci_core::{
    ContextValue, JobAuthorityProfile, JobContentReference, JobExecutionContext,
    JobInstanceIdentity, JobIr, JobIrEnvelope, JobRuntimeContext, JobSource, RunId,
    RunValueTemplates, RunnerRequirements, RuntimeBoolean, SemanticStep, Sha256Digest,
    ShellTemplate, StepId, StepIr, StrategyContext, UnixMillis, ValueTemplate, WorkflowId,
    WorkflowJobKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation,
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ClaimProviderDelivery, ClaimedLogicalActivationPreparation,
    ClaimedLogicalInstanceMaterialization, ClaimedLogicalJobActivation,
    CommitLogicalInstanceMaterialization, ConsumeSelectedLogicalInstanceMaterialization,
    ConsumeSelectedLogicalJobOrchestration, ConsumedLogicalJobOrchestrationAuthority,
    ConsumedSelectedLogicalInstanceMaterialization, ConsumedSelectedLogicalJobOrchestration,
    EnsureGithubServerServiceAuthority, GithubCheckHeadSha, GithubCheckName,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    JobEnvironmentActivationEvidence, JobEventTrust, JobSourceKind, LogicalActivationClaimFence,
    LogicalActivationObject, LogicalActivationPreparationClaimFence,
    LogicalActivationPreparationStore as _, LogicalActivationPreparationStoreError,
    LogicalActivationRepository as _, LogicalActivationStoreError, LogicalActivationWorkerId,
    LogicalInstanceMaterializationSelectionOutcome, LogicalJobOrchestrationSelectionOutcome,
    LogicalMaterializationClaimFence, LogicalMaterializationRepository as _,
    LogicalMaterializationStoreError, LogicalMaterializationWorkerId, LogicalWorkQuarantineKind,
    LogicalWorkQuarantineOutcome, LogicalWorkSelectionId, LogicalWorkSelectionRepository as _,
    LogicalWorkSelectionStoreError, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind, ObjectKey,
    ProviderConnectionId, ProviderDeliveryClaimOwnerId, ProviderDeliveryIdentity,
    ProviderDeliveryRepository as _, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    PublishLogicalJobActivation, QuarantineLogicalInstanceMaterialization,
    QuarantineLogicalJobOrchestration, RenewLogicalActivationPreparation,
    RenewLogicalInstanceMaterialization, RenewLogicalJobActivation,
    RenewedLogicalActivationPreparation, RenewedLogicalInstanceMaterialization,
    RenewedLogicalJobActivation, ReusableSecretPermission, SelectedLogicalInstanceMaterialization,
    SelectedLogicalJobOrchestration, StoreError, TenantScope, WorkflowAdmissionIdempotency,
    WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::support::{TestClock, TestDatabase, TestResult, run_with_database};

const INITIAL_SELECTION_MILLIS: i64 = 2_000;
const FIRST_RENEWAL_MILLIS: i64 = 60_000;
const SECOND_RENEWAL_MILLIS: i64 = 120_000;
const NEW_RENEWAL_MILLIS: i64 = 180_000;

struct Fixture {
    tenant: String,
    namespace: u128,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    jobs: [LogicalWorkflowJobId; 4],
}

struct PreparedInstance {
    activated: ActivatedLogicalInstanceDescriptor,
    envelope: JobIrEnvelope,
    encoded: Vec<u8>,
    runtime_context: JobRuntimeContext,
    runtime_encoded: Vec<u8>,
}

struct OrchestrationSelection {
    request: ClaimNextLogicalJobOrchestration,
    selected: SelectedLogicalJobOrchestration,
    consumed: ConsumedSelectedLogicalJobOrchestration,
}

struct MaterializationSelection {
    request: ClaimNextLogicalInstanceMaterialization,
    selected: SelectedLogicalInstanceMaterialization,
    consumed: ConsumedSelectedLogicalInstanceMaterialization,
}

struct PreparationRenewalChain {
    first_request: RenewLogicalActivationPreparation,
    first_ack: RenewedLogicalActivationPreparation,
    current: ConsumedSelectedLogicalJobOrchestration,
}

struct ActivationRenewalChain {
    first_request: RenewLogicalJobActivation,
    first_ack: RenewedLogicalJobActivation,
    current: ConsumedSelectedLogicalJobOrchestration,
}

struct MaterializationRenewalChain {
    first_request: RenewLogicalInstanceMaterialization,
    first_ack: RenewedLogicalInstanceMaterialization,
    current: ConsumedSelectedLogicalInstanceMaterialization,
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn renewal_ack_is_replayable_but_never_authorizes_work() -> TestResult {
    run_with_database(|database| async move {
        let mut terminal = fixture(&database, "renewal-ack-terminal", 700_000, 0).await?;
        seed_tenant(&database, &terminal.tenant).await?;
        admit_authenticated_fixture(&database, &mut terminal).await?;
        exercise_terminal_preparation(&database, &terminal).await?;
        let terminal_instance =
            Box::pin(exercise_terminal_activation(&database, &terminal)).await?;
        exercise_terminal_materialization(&database, &terminal, &terminal_instance).await?;

        let mut quarantined_preparation =
            fixture(&database, "renewal-ack-preparation-q", 710_000, 1).await?;
        seed_tenant(&database, &quarantined_preparation.tenant).await?;
        admit_authenticated_fixture(&database, &mut quarantined_preparation).await?;
        exercise_quarantined_preparation(&database, &quarantined_preparation).await?;

        let mut quarantined_activation =
            fixture(&database, "renewal-ack-activation-q", 720_000, 2).await?;
        seed_tenant(&database, &quarantined_activation.tenant).await?;
        admit_authenticated_fixture(&database, &mut quarantined_activation).await?;
        prepare_without_renewal(
            &database,
            &quarantined_activation,
            quarantined_activation.jobs[2],
            20_005,
        )
        .await?;
        exercise_quarantined_activation(&database, &quarantined_activation).await?;

        let mut quarantined_materialization =
            fixture(&database, "renewal-ack-materialization-q", 730_000, 3).await?;
        seed_tenant(&database, &quarantined_materialization.tenant).await?;
        admit_authenticated_fixture(&database, &mut quarantined_materialization).await?;
        prepare_without_renewal(
            &database,
            &quarantined_materialization,
            quarantined_materialization.jobs[3],
            20_007,
        )
        .await?;
        let quarantined_instance = publish_without_renewal(
            &database,
            &quarantined_materialization,
            quarantined_materialization.jobs[3],
            20_008,
        )
        .await?;
        exercise_quarantined_materialization(
            &database,
            &quarantined_materialization,
            &quarantined_instance,
        )
        .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One poison transaction proves lock, reciprocity, and queue progress.
async fn activation_generation_poison_is_locked_exact_and_does_not_starve_new_work() -> TestResult {
    run_with_database(|database| async move {
        let mut poisoned = fixture(&database, "activation-poison", 740_000, 0).await?;
        seed_tenant(&database, &poisoned.tenant).await?;
        admit_authenticated_fixture(&database, &mut poisoned).await?;
        prepare_without_renewal(&database, &poisoned, poisoned.jobs[0], 30_001).await?;
        let activation =
            select_orchestration(&database, &poisoned, poisoned.jobs[0], 30_002, 40_002).await?;
        let initial_claim = activation_authority(&activation.consumed)?.claim().clone();

        let mut corruption = database.pool().begin().await?;
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *corruption)
            .await?;
        let corrupted = sqlx::query(
            r"
            UPDATE logical_workflow_jobs
            SET activation_fence = $2,
                created_at_ms = 1,
                activation_claimed_at_ms = 1,
                activation_expires_at_ms = 2001,
                updated_at_ms = 1
            WHERE id = $1 AND state = 'activating'
            ",
        )
        .bind(poisoned.jobs[0].as_uuid())
        .bind(i64::MAX)
        .execute(&mut *corruption)
        .await?
        .rows_affected();
        assert_eq!(corrupted, 1);
        corruption.commit().await?;

        let mut authority_lock = database.pool().begin().await?;
        sqlx::query("SELECT id FROM logical_workflow_jobs WHERE id = $1 FOR UPDATE")
            .bind(poisoned.jobs[0].as_uuid())
            .fetch_one(&mut *authority_lock)
            .await?;
        let contended_request = ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(30_003))?,
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(40_003))?,
            UnixMillis::new(database_now_ms(&database).await?),
            INITIAL_SELECTION_MILLIS,
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_orchestration(contended_request.clone())
                .await?,
            LogicalJobOrchestrationSelectionOutcome::Contended
        ));
        let contended_outcome: String = sqlx::query_scalar(
            "SELECT outcome FROM logical_workflow_activation_work_selections WHERE selection_id = $1",
        )
        .bind(contended_request.selection_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(contended_outcome, "contended");
        let quarantine_count: i64 = sqlx::query_scalar(
            "SELECT count(*)::BIGINT FROM logical_workflow_activation_work_quarantines",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(quarantine_count, 0);
        authority_lock.commit().await?;

        let poison_request = ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(30_004))?,
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(40_004))?,
            UnixMillis::new(database_now_ms(&database).await?),
            INITIAL_SELECTION_MILLIS,
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
                .claim_next_logical_job_orchestration(poison_request.clone())
                .await?,
            LogicalJobOrchestrationSelectionOutcome::Quarantined
        ));

        let poison_receipt: (String, Option<i64>, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT outcome, generation, logical_job_id
            FROM logical_workflow_activation_work_selections
            WHERE selection_id = $1
            ",
        )
        .bind(poison_request.selection_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(poison_receipt.0, "quarantined");
        assert_eq!(poison_receipt.1, Some(i64::MAX));
        assert_eq!(poison_receipt.2, Some(poisoned.jobs[0].as_uuid()));
        let poison: (String, i64, Uuid) = sqlx::query_as(
            r"
            SELECT failure_kind, authority_generation, selection_id
            FROM logical_workflow_activation_work_quarantines
            WHERE logical_job_id = $1
            ",
        )
        .bind(poisoned.jobs[0].as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(poison.0, "generation_exhausted");
        assert_eq!(poison.1, i64::MAX);
        assert_eq!(poison.2, poison_request.selection_id().as_uuid());
        assert_activation_poison_reciprocity(
            &database,
            poison_request.selection_id(),
            poisoned.jobs[0],
            poisoned.jobs[1],
        )
        .await?;
        let selecting_count: i64 = sqlx::query_scalar(
            "SELECT count(*)::BIGINT FROM logical_workflow_activation_work_selections WHERE outcome = 'selecting'",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(selecting_count, 0);
        assert!(matches!(
            consume_orchestration(&database, activation.selected).await,
            Err(LogicalWorkSelectionStoreError::SelectionQuarantined)
        ));
        assert!(matches!(
            database
                .store()
                .renew_logical_job_activation(RenewLogicalJobActivation::new(
                    initial_claim,
                    FIRST_RENEWAL_MILLIS,
                )?)
                .await,
            Err(LogicalActivationStoreError::ClaimRejected)
        ));

        let mut newer = fixture(&database, "activation-poison-newer", 750_000, 0).await?;
        seed_tenant(&database, &newer.tenant).await?;
        admit_authenticated_fixture(&database, &mut newer).await?;
        select_orchestration(&database, &newer, newer.jobs[0], 30_005, 40_005).await?;
        delete_activation_quarantine_and_assert_replay_corrupt(
            &database,
            poisoned.jobs[0],
            poison_request,
        )
        .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One poison scenario proves materialization lock, replay, and progress.
async fn materialization_generation_poison_is_locked_exact_and_does_not_starve_new_work()
-> TestResult {
    run_with_database(|database| async move {
        let mut poisoned = fixture(&database, "materialization-poison", 745_000, 0).await?;
        seed_tenant(&database, &poisoned.tenant).await?;
        admit_authenticated_fixture(&database, &mut poisoned).await?;
        prepare_without_renewal(&database, &poisoned, poisoned.jobs[0], 32_001).await?;
        let prepared =
            publish_without_renewal(&database, &poisoned, poisoned.jobs[0], 32_002).await?;
        let materialization = select_materialization(
            &database,
            &poisoned,
            poisoned.jobs[0],
            prepared.activated.id(),
            32_003,
            42_003,
        )
        .await?;
        let initial_claim = materialization.consumed.authority().claim().clone();

        let mut corruption = database.pool().begin().await?;
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *corruption)
            .await?;
        let corrupted = sqlx::query(
            r"
            UPDATE logical_workflow_materialization_claims
            SET generation = $2, created_at_ms = 1, claimed_at_ms = 1,
                expires_at_ms = 2001, updated_at_ms = 1
            WHERE instance_id = $1 AND state = 'materializing'
            ",
        )
        .bind(prepared.activated.id().as_uuid())
        .bind(i64::MAX)
        .execute(&mut *corruption)
        .await?
        .rows_affected();
        assert_eq!(corrupted, 1);
        corruption.commit().await?;

        let mut authority_lock = database.pool().begin().await?;
        sqlx::query(
            "SELECT instance_id FROM logical_workflow_materialization_claims WHERE instance_id = $1 FOR UPDATE",
        )
        .bind(prepared.activated.id().as_uuid())
        .fetch_one(&mut *authority_lock)
        .await?;
        let contended_request = ClaimNextLogicalInstanceMaterialization::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(32_004))?,
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(42_004))?,
            UnixMillis::new(database_now_ms(&database).await?),
            INITIAL_SELECTION_MILLIS,
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(contended_request.clone())
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Contended
        ));
        let contended_outcome: String = sqlx::query_scalar(
            "SELECT outcome FROM logical_workflow_materialization_work_selections WHERE selection_id = $1",
        )
        .bind(contended_request.selection_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(contended_outcome, "contended");
        let quarantine_count: i64 = sqlx::query_scalar(
            "SELECT count(*)::BIGINT FROM logical_workflow_materialization_work_quarantines",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(quarantine_count, 0);
        authority_lock.commit().await?;

        let poison_request = ClaimNextLogicalInstanceMaterialization::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(32_005))?,
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(42_005))?,
            UnixMillis::new(database_now_ms(&database).await?),
            INITIAL_SELECTION_MILLIS,
        )?;
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
                .claim_next_logical_instance_materialization(poison_request.clone())
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Quarantined
        ));
        let poison_receipt: (String, Option<i64>, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT outcome, generation, instance_id
            FROM logical_workflow_materialization_work_selections
            WHERE selection_id = $1
            ",
        )
        .bind(poison_request.selection_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(poison_receipt.0, "quarantined");
        assert_eq!(poison_receipt.1, Some(i64::MAX));
        assert_eq!(poison_receipt.2, Some(prepared.activated.id().as_uuid()));
        let poison: (String, i64, Uuid) = sqlx::query_as(
            r"
            SELECT failure_kind, authority_generation, selection_id
            FROM logical_workflow_materialization_work_quarantines
            WHERE instance_id = $1
            ",
        )
        .bind(prepared.activated.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(poison.0, "generation_exhausted");
        assert_eq!(poison.1, i64::MAX);
        assert_eq!(poison.2, poison_request.selection_id().as_uuid());
        assert_materialization_poison_reciprocity(
            &database,
            poison_request.selection_id(),
            prepared.activated.id(),
            Uuid::from_u128(32_099),
        )
        .await?;
        assert!(matches!(
            consume_materialization(&database, materialization.selected).await,
            Err(LogicalWorkSelectionStoreError::SelectionQuarantined)
        ));
        assert!(matches!(
            database
                .store()
                .renew_logical_instance_materialization(
                    RenewLogicalInstanceMaterialization::new(
                        initial_claim,
                        FIRST_RENEWAL_MILLIS,
                    )?,
                )
                .await,
            Err(LogicalMaterializationStoreError::ClaimRejected)
        ));

        let mut newer = fixture(&database, "materialization-poison-newer", 755_000, 0).await?;
        seed_tenant(&database, &newer.tenant).await?;
        admit_authenticated_fixture(&database, &mut newer).await?;
        prepare_without_renewal(&database, &newer, newer.jobs[0], 32_006).await?;
        let newer_prepared =
            publish_without_renewal(&database, &newer, newer.jobs[0], 32_007).await?;
        select_materialization(
            &database,
            &newer,
            newer.jobs[0],
            newer_prepared.activated.id(),
            32_008,
            42_008,
        )
        .await?;
        corrupt_materialization_quarantine_failure_and_assert_replay_corrupt(
            &database,
            prepared.activated.id(),
            poison_request,
        )
        .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn legacy_null_preparation_origin_rejects_live_consume_and_allows_takeover() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let mut preparation = fixture(&database, "legacy-null-preparation", 760_000, 0).await?;
        seed_tenant(&database, &preparation.tenant).await?;
        admit_authenticated_fixture(&database, &mut preparation).await?;
        let first_preparation =
            select_orchestration(&database, &preparation, preparation.jobs[0], 31_001, 41_001)
                .await?;
        let first_preparation_authority = preparation_authority(&first_preparation.consumed)?;
        let first_renewal_request = RenewLogicalActivationPreparation::new(
            first_preparation_authority.claim().clone(),
            FIRST_RENEWAL_MILLIS,
        )?;
        let first_renewal_ack = database
            .store()
            .renew_logical_activation_preparation(first_renewal_request.clone())
            .await?;
        clear_preparation_origin(&database, preparation.jobs[0]).await?;
        assert!(matches!(
            consume_orchestration(&database, first_preparation.selected.clone()).await,
            Err(LogicalWorkSelectionStoreError::SelectionExpired)
        ));
        expire_preparation_claim(&database, &clock, preparation.jobs[0]).await?;
        let preparation_takeover =
            select_orchestration(&database, &preparation, preparation.jobs[0], 31_002, 41_002)
                .await?;
        let preparation_authority = preparation_authority(&preparation_takeover.consumed)?;
        assert_eq!(
            preparation_authority.claim().generation().get(),
            first_renewal_ack.successor_generation().get() + 1
        );
        assert_eq!(
            preparation_authority.claim().selection_origin(),
            preparation_takeover.request.selection_id()
        );
        assert_eq!(
            database
                .store()
                .renew_logical_activation_preparation(first_renewal_request)
                .await?,
            first_renewal_ack
        );
        assert_eq!(
            database
                .store()
                .quarantine_logical_job_orchestration(QuarantineLogicalJobOrchestration::new(
                    preparation_takeover.consumed,
                    LogicalWorkQuarantineKind::RelationalEvidence,
                ))
                .await?,
            LogicalWorkQuarantineOutcome::Quarantined
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn legacy_null_activation_origin_rejects_live_consume_and_allows_takeover() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let mut activation = fixture(&database, "legacy-null-activation", 770_000, 0).await?;
        seed_tenant(&database, &activation.tenant).await?;
        admit_authenticated_fixture(&database, &mut activation).await?;
        prepare_without_renewal(&database, &activation, activation.jobs[0], 31_003).await?;
        let first_activation =
            select_orchestration(&database, &activation, activation.jobs[0], 31_004, 41_004)
                .await?;
        let first_selection_request = first_activation.request.clone();
        let first_activation_authority = activation_authority(&first_activation.consumed)?;
        let first_renewal_request = RenewLogicalJobActivation::new(
            first_activation_authority.claim().clone(),
            FIRST_RENEWAL_MILLIS,
        )?;
        let first_renewal_ack = database
            .store()
            .renew_logical_job_activation(first_renewal_request.clone())
            .await?;
        clear_activation_origin(&database, activation.jobs[0]).await?;
        assert!(matches!(
            consume_orchestration(&database, first_activation.selected.clone()).await,
            Err(LogicalWorkSelectionStoreError::SelectionExpired)
        ));
        expire_activation_claim(&database, &clock, activation.jobs[0]).await?;
        let legacy: (String, Option<Uuid>, i64, i64, bool) = sqlx::query_as(
            r"
            SELECT job.state, job.activation_origin_selection_id,
                   job.activation_expires_at_ms,
                   floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT,
                   preparation.logical_job_id IS NOT NULL
            FROM logical_workflow_jobs AS job
            LEFT JOIN logical_workflow_activation_preparations AS preparation
              ON preparation.logical_job_id = job.id
            WHERE job.id = $1
            ",
        )
        .bind(activation.jobs[0].as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(legacy.0, "activating");
        assert_eq!(legacy.1, None);
        assert!(legacy.2 <= legacy.3);
        assert!(legacy.4);
        let activation_takeover =
            select_orchestration(&database, &activation, activation.jobs[0], 31_005, 41_005)
                .await?;
        let activation_authority = activation_authority(&activation_takeover.consumed)?;
        assert_eq!(
            activation_authority.claim().generation().get(),
            first_renewal_ack.successor_generation().get() + 1
        );
        assert_eq!(
            activation_authority.claim().selection_origin(),
            activation_takeover.request.selection_id()
        );
        assert_eq!(
            database
                .store()
                .renew_logical_job_activation(first_renewal_request)
                .await?,
            first_renewal_ack
        );
        assert_eq!(
            database
                .store()
                .quarantine_logical_job_orchestration(QuarantineLogicalJobOrchestration::new(
                    activation_takeover.consumed,
                    LogicalWorkQuarantineKind::RelationalEvidence,
                ))
                .await?,
            LogicalWorkQuarantineOutcome::Quarantined
        );
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_orchestration(first_selection_request)
                .await,
            Err(LogicalWorkSelectionStoreError::SelectionExpired)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn legacy_null_materialization_origin_rejects_live_consume_and_allows_takeover() -> TestResult
{
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let mut materialization =
            fixture(&database, "legacy-null-materialization", 780_000, 0).await?;
        seed_tenant(&database, &materialization.tenant).await?;
        admit_authenticated_fixture(&database, &mut materialization).await?;
        prepare_without_renewal(&database, &materialization, materialization.jobs[0], 31_006)
            .await?;
        let instance =
            publish_without_renewal(&database, &materialization, materialization.jobs[0], 31_007)
                .await?;
        let first_materialization = select_materialization(
            &database,
            &materialization,
            materialization.jobs[0],
            instance.activated.id(),
            31_008,
            41_008,
        )
        .await?;
        let first_selection_request = first_materialization.request.clone();
        let first_materialization_authority = first_materialization.consumed.authority().clone();
        let first_renewal_request = RenewLogicalInstanceMaterialization::new(
            first_materialization_authority.claim().clone(),
            FIRST_RENEWAL_MILLIS,
        )?;
        let first_renewal_ack = database
            .store()
            .renew_logical_instance_materialization(first_renewal_request.clone())
            .await?;
        clear_materialization_origin(&database, instance.activated.id()).await?;
        assert!(matches!(
            consume_materialization(&database, first_materialization.selected.clone()).await,
            Err(LogicalWorkSelectionStoreError::SelectionExpired)
        ));
        expire_materialization_claim(&database, &clock, instance.activated.id()).await?;
        let materialization_takeover = select_materialization(
            &database,
            &materialization,
            materialization.jobs[0],
            instance.activated.id(),
            31_009,
            41_009,
        )
        .await?;
        assert_eq!(
            materialization_takeover
                .consumed
                .authority()
                .claim()
                .generation()
                .get(),
            first_renewal_ack.successor_generation().get() + 1
        );
        assert_eq!(
            materialization_takeover
                .consumed
                .authority()
                .claim()
                .selection_origin(),
            materialization_takeover.request.selection_id()
        );
        assert_eq!(
            database
                .store()
                .renew_logical_instance_materialization(first_renewal_request)
                .await?,
            first_renewal_ack
        );
        assert_eq!(
            database
                .store()
                .quarantine_logical_instance_materialization(
                    QuarantineLogicalInstanceMaterialization::new(
                        materialization_takeover.consumed,
                        LogicalWorkQuarantineKind::RelationalEvidence,
                    ),
                )
                .await?,
            LogicalWorkQuarantineOutcome::Quarantined
        );
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(first_selection_request)
                .await,
            Err(LogicalWorkSelectionStoreError::SelectionExpired)
        ));
        Ok(())
    })
    .await
}

async fn clear_preparation_origin(
    database: &TestDatabase,
    logical_job_id: LogicalWorkflowJobId,
) -> TestResult {
    set_replica_update(
        database,
        "UPDATE logical_workflow_activation_preparation_claims SET origin_selection_id = NULL WHERE logical_job_id = $1",
        logical_job_id.as_uuid(),
    )
    .await
}

async fn expire_preparation_claim(
    database: &TestDatabase,
    clock: &TestClock,
    logical_job_id: LogicalWorkflowJobId,
) -> TestResult {
    wait_for_database_expiry(
        database,
        clock,
        "SELECT expires_at_ms FROM logical_workflow_activation_preparation_claims WHERE logical_job_id = $1",
        logical_job_id.as_uuid(),
    )
    .await
}

async fn clear_activation_origin(
    database: &TestDatabase,
    logical_job_id: LogicalWorkflowJobId,
) -> TestResult {
    set_replica_update(
        database,
        "UPDATE logical_workflow_jobs SET activation_origin_selection_id = NULL WHERE id = $1",
        logical_job_id.as_uuid(),
    )
    .await
}

async fn expire_activation_claim(
    database: &TestDatabase,
    clock: &TestClock,
    logical_job_id: LogicalWorkflowJobId,
) -> TestResult {
    wait_for_database_expiry(
        database,
        clock,
        "SELECT activation_expires_at_ms FROM logical_workflow_jobs WHERE id = $1",
        logical_job_id.as_uuid(),
    )
    .await
}

async fn clear_materialization_origin(
    database: &TestDatabase,
    instance_id: automata_ci_store::LogicalWorkflowInstanceId,
) -> TestResult {
    set_replica_update(
        database,
        "UPDATE logical_workflow_materialization_claims SET origin_selection_id = NULL WHERE instance_id = $1",
        instance_id.as_uuid(),
    )
    .await
}

async fn expire_materialization_claim(
    database: &TestDatabase,
    clock: &TestClock,
    instance_id: automata_ci_store::LogicalWorkflowInstanceId,
) -> TestResult {
    wait_for_database_expiry(
        database,
        clock,
        "SELECT expires_at_ms FROM logical_workflow_materialization_claims WHERE instance_id = $1",
        instance_id.as_uuid(),
    )
    .await
}

async fn wait_for_database_expiry(
    database: &TestDatabase,
    clock: &TestClock,
    statement: &'static str,
    id: Uuid,
) -> TestResult {
    let expires_at: i64 = sqlx::query_scalar(statement)
        .bind(id)
        .fetch_one(database.pool())
        .await?;
    clock
        .set(
            expires_at
                .checked_add(50)
                .ok_or("logical claim expiry clock overflow")?,
        )
        .await?;
    Ok(())
}

async fn set_replica_update(
    database: &TestDatabase,
    statement: &'static str,
    id: Uuid,
) -> TestResult {
    let mut transaction = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *transaction)
        .await?;
    let rows = sqlx::query(statement)
        .bind(id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    assert_eq!(rows, 1);
    transaction.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // The deferred reciprocal guard requires one intentionally contradictory transaction.
async fn assert_activation_poison_reciprocity(
    database: &TestDatabase,
    selection_id: LogicalWorkSelectionId,
    poisoned_job: LogicalWorkflowJobId,
    distinct_job: LogicalWorkflowJobId,
) -> TestResult {
    let mut contradictory = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *contradictory)
        .await?;
    sqlx::query(
        r"
        CREATE TEMPORARY TABLE activation_poison_copy ON COMMIT DROP AS
        SELECT *
        FROM logical_workflow_activation_work_quarantines
        WHERE logical_job_id = $1
        ",
    )
    .bind(poisoned_job.as_uuid())
    .execute(&mut *contradictory)
    .await?;
    sqlx::query(
        "DELETE FROM logical_workflow_activation_work_quarantines WHERE logical_job_id = $1",
    )
    .bind(poisoned_job.as_uuid())
    .execute(&mut *contradictory)
    .await?;
    sqlx::query(
        r"
        UPDATE logical_workflow_activation_work_selections
        SET outcome = 'selecting', claimed_at_ms = NULL, expires_at_ms = NULL,
            tenant_id = NULL, run_id = NULL, invocation_id = NULL,
            logical_job_id = NULL, generation = NULL, authority_kind = NULL,
            authority_digest = NULL
        WHERE selection_id = $1
        ",
    )
    .bind(selection_id.as_uuid())
    .execute(&mut *contradictory)
    .await?;
    sqlx::query("SET LOCAL session_replication_role = origin")
        .execute(&mut *contradictory)
        .await?;
    sqlx::query(
        r"
        INSERT INTO logical_workflow_activation_work_quarantines
        SELECT * FROM activation_poison_copy
        ",
    )
    .execute(&mut *contradictory)
    .await?;
    sqlx::query(
        r"
        UPDATE logical_workflow_activation_work_selections AS selection
        SET outcome = 'contended',
            claimed_at_ms = poison.selection_claimed_at_ms,
            expires_at_ms = poison.selection_expires_at_ms
        FROM activation_poison_copy AS poison
        WHERE selection.selection_id = $1
        ",
    )
    .bind(selection_id.as_uuid())
    .execute(&mut *contradictory)
    .await?;
    let error = contradictory
        .commit()
        .await
        .expect_err("generation poison cannot finalize its parent as contended");
    assert_database_constraint(
        &error,
        "23514",
        "workflow_activation_quarantine_parent_final_exact",
    );

    let mut duplicate = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *duplicate)
        .await?;
    let error = sqlx::query(
        r"
        INSERT INTO logical_workflow_activation_work_quarantines (
            logical_job_id, tenant_id, run_id, invocation_id,
            selection_id, selection_owner_id, selection_requested_at_ms,
            selection_duration_ms, selection_generation,
            selection_claimed_at_ms, selection_expires_at_ms, authority_kind,
            authority_digest, authority_owner_id, authority_generation,
            authority_claimed_at_ms, authority_expires_at_ms, failure_kind,
            quarantined_at_ms
        )
        SELECT $2, tenant_id, run_id, invocation_id,
               selection_id, selection_owner_id, selection_requested_at_ms,
               selection_duration_ms, selection_generation,
               selection_claimed_at_ms, selection_expires_at_ms, authority_kind,
               authority_digest, authority_owner_id, authority_generation,
               authority_claimed_at_ms, authority_expires_at_ms, failure_kind,
               quarantined_at_ms
        FROM logical_workflow_activation_work_quarantines
        WHERE logical_job_id = $1
        ",
    )
    .bind(poisoned_job.as_uuid())
    .bind(distinct_job.as_uuid())
    .execute(&mut *duplicate)
    .await
    .expect_err("one selection cannot parent two quarantine targets");
    assert_database_constraint(
        &error,
        "23505",
        "logical_workflow_activation_quarantine_selection_unique",
    );
    duplicate.rollback().await?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // The deferred reciprocal guard requires one intentionally contradictory transaction.
async fn assert_materialization_poison_reciprocity(
    database: &TestDatabase,
    selection_id: LogicalWorkSelectionId,
    poisoned_instance: automata_ci_store::LogicalWorkflowInstanceId,
    distinct_instance: Uuid,
) -> TestResult {
    let mut contradictory = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *contradictory)
        .await?;
    sqlx::query(
        r"
        CREATE TEMPORARY TABLE materialization_poison_copy ON COMMIT DROP AS
        SELECT *
        FROM logical_workflow_materialization_work_quarantines
        WHERE instance_id = $1
        ",
    )
    .bind(poisoned_instance.as_uuid())
    .execute(&mut *contradictory)
    .await?;
    sqlx::query(
        "DELETE FROM logical_workflow_materialization_work_quarantines WHERE instance_id = $1",
    )
    .bind(poisoned_instance.as_uuid())
    .execute(&mut *contradictory)
    .await?;
    sqlx::query(
        r"
        UPDATE logical_workflow_materialization_work_selections
        SET outcome = 'selecting', claimed_at_ms = NULL, expires_at_ms = NULL,
            tenant_id = NULL, run_id = NULL, invocation_id = NULL,
            logical_job_id = NULL, instance_id = NULL, generation = NULL,
            authority_digest = NULL
        WHERE selection_id = $1
        ",
    )
    .bind(selection_id.as_uuid())
    .execute(&mut *contradictory)
    .await?;
    sqlx::query("SET LOCAL session_replication_role = origin")
        .execute(&mut *contradictory)
        .await?;
    sqlx::query(
        r"
        INSERT INTO logical_workflow_materialization_work_quarantines
        SELECT * FROM materialization_poison_copy
        ",
    )
    .execute(&mut *contradictory)
    .await?;
    sqlx::query(
        r"
        UPDATE logical_workflow_materialization_work_selections AS selection
        SET outcome = 'contended',
            claimed_at_ms = poison.selection_claimed_at_ms,
            expires_at_ms = poison.selection_expires_at_ms
        FROM materialization_poison_copy AS poison
        WHERE selection.selection_id = $1
        ",
    )
    .bind(selection_id.as_uuid())
    .execute(&mut *contradictory)
    .await?;
    let error = contradictory
        .commit()
        .await
        .expect_err("generation poison cannot finalize its parent as contended");
    assert_database_constraint(
        &error,
        "23514",
        "workflow_materialization_quarantine_parent_final_exact",
    );

    let mut duplicate = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *duplicate)
        .await?;
    let error = sqlx::query(
        r"
        INSERT INTO logical_workflow_materialization_work_quarantines (
            instance_id, tenant_id, run_id, invocation_id, logical_job_id,
            selection_id, selection_owner_id, selection_requested_at_ms,
            selection_duration_ms, selection_generation,
            selection_claimed_at_ms, selection_expires_at_ms, authority_digest,
            authority_owner_id, authority_generation, authority_claimed_at_ms,
            authority_expires_at_ms, failure_kind, quarantined_at_ms
        )
        SELECT $2, tenant_id, run_id, invocation_id, logical_job_id,
               selection_id, selection_owner_id, selection_requested_at_ms,
               selection_duration_ms, selection_generation,
               selection_claimed_at_ms, selection_expires_at_ms, authority_digest,
               authority_owner_id, authority_generation, authority_claimed_at_ms,
               authority_expires_at_ms, failure_kind, quarantined_at_ms
        FROM logical_workflow_materialization_work_quarantines
        WHERE instance_id = $1
        ",
    )
    .bind(poisoned_instance.as_uuid())
    .bind(distinct_instance)
    .execute(&mut *duplicate)
    .await
    .expect_err("one selection cannot parent two quarantine targets");
    assert_database_constraint(
        &error,
        "23505",
        "logical_workflow_materialization_quarantine_selection_unique",
    );
    duplicate.rollback().await?;
    Ok(())
}

fn assert_database_constraint(error: &sqlx::Error, expected_code: &str, expected: &str) {
    let database = error.as_database_error().expect("database error");
    assert_eq!(database.code().as_deref(), Some(expected_code));
    assert_eq!(database.constraint(), Some(expected));
}

async fn exercise_terminal_preparation(database: &TestDatabase, fixture: &Fixture) -> TestResult {
    let preparation =
        select_orchestration(database, fixture, fixture.jobs[0], 10_001, 20_001).await?;
    let initial = preparation_authority(&preparation.consumed)?;
    let chain = renew_preparation_chain(database, &preparation.selected, &initial).await?;
    let current = preparation_authority(&chain.current)?;
    let current_claim = current.claim().clone();
    bind_preparation(database, &current, "terminal-preparation").await?;
    assert_eq!(
        database
            .store()
            .renew_logical_activation_preparation(chain.first_request.clone())
            .await?,
        chain.first_ack
    );
    assert!(matches!(
        consume_orchestration(database, preparation.selected.clone()).await,
        Err(LogicalWorkSelectionStoreError::SelectionExpired)
    ));
    let new_request = RenewLogicalActivationPreparation::new(current_claim, NEW_RENEWAL_MILLIS)?;
    assert!(matches!(
        database
            .store()
            .renew_logical_activation_preparation(new_request)
            .await,
        Err(LogicalActivationPreparationStoreError::ClaimRejected)
    ));
    Ok(())
}

async fn exercise_terminal_activation(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult<PreparedInstance> {
    let activation =
        select_orchestration(database, fixture, fixture.jobs[0], 10_002, 20_002).await?;
    let initial = activation_authority(&activation.consumed)?;
    let chain = renew_activation_chain(database, &activation.selected, &initial).await?;
    let current = activation_authority(&chain.current)?;
    let current_claim = current.claim().clone();
    let prepared = prepared_instance(fixture, &current, "terminal");
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            current.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    assert_eq!(
        database
            .store()
            .renew_logical_job_activation(chain.first_request.clone())
            .await?,
        chain.first_ack
    );
    assert!(matches!(
        consume_orchestration(database, activation.selected.clone()).await,
        Err(LogicalWorkSelectionStoreError::SelectionExpired)
    ));
    let new_request = RenewLogicalJobActivation::new(current_claim, NEW_RENEWAL_MILLIS)?;
    assert!(matches!(
        database
            .store()
            .renew_logical_job_activation(new_request)
            .await,
        Err(LogicalActivationStoreError::ClaimRejected)
    ));
    Ok(prepared)
}

async fn exercise_terminal_materialization(
    database: &TestDatabase,
    fixture: &Fixture,
    prepared: &PreparedInstance,
) -> TestResult {
    let materialization = select_materialization(
        database,
        fixture,
        fixture.jobs[0],
        prepared.activated.id(),
        10_003,
        20_003,
    )
    .await?;
    let initial = materialization.consumed.authority().clone();
    let chain = renew_materialization_chain(database, &materialization.selected, &initial).await?;
    let current = chain.current.authority().clone();
    let current_claim = current.claim().clone();
    database
        .store()
        .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
            &current,
            &prepared.encoded,
            &prepared.envelope,
            &prepared.runtime_encoded,
            &prepared.runtime_context,
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    assert_eq!(
        database
            .store()
            .renew_logical_instance_materialization(chain.first_request.clone())
            .await?,
        chain.first_ack
    );
    assert!(matches!(
        consume_materialization(database, materialization.selected.clone()).await,
        Err(LogicalWorkSelectionStoreError::SelectionExpired)
    ));
    let new_request = RenewLogicalInstanceMaterialization::new(current_claim, NEW_RENEWAL_MILLIS)?;
    assert!(matches!(
        database
            .store()
            .renew_logical_instance_materialization(new_request)
            .await,
        Err(LogicalMaterializationStoreError::ClaimRejected)
    ));
    Ok(())
}

async fn exercise_quarantined_preparation(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult {
    let selection =
        select_orchestration(database, fixture, fixture.jobs[1], 10_004, 20_004).await?;
    let initial = preparation_authority(&selection.consumed)?;
    let chain = renew_preparation_chain(database, &selection.selected, &initial).await?;
    let current = preparation_authority(&chain.current)?;
    let new_request =
        RenewLogicalActivationPreparation::new(current.claim().clone(), NEW_RENEWAL_MILLIS)?;
    assert_eq!(
        database
            .store()
            .quarantine_logical_job_orchestration(QuarantineLogicalJobOrchestration::new(
                chain.current.clone(),
                LogicalWorkQuarantineKind::PayloadEvidence,
            ))
            .await?,
        LogicalWorkQuarantineOutcome::Quarantined
    );
    assert_ordinary_activation_quarantine(
        database,
        selection.selected.selection_id(),
        "payload_evidence",
    )
    .await?;
    assert_eq!(
        database
            .store()
            .renew_logical_activation_preparation(chain.first_request)
            .await?,
        chain.first_ack
    );
    assert!(matches!(
        consume_orchestration(database, selection.selected).await,
        Err(LogicalWorkSelectionStoreError::SelectionQuarantined)
    ));
    assert!(matches!(
        database
            .store()
            .renew_logical_activation_preparation(new_request)
            .await,
        Err(LogicalActivationPreparationStoreError::ClaimRejected)
    ));
    assert!(matches!(
        database
            .store()
            .claim_next_logical_job_orchestration(selection.request)
            .await?,
        LogicalJobOrchestrationSelectionOutcome::Quarantined
    ));
    Ok(())
}

async fn exercise_quarantined_activation(database: &TestDatabase, fixture: &Fixture) -> TestResult {
    let selection =
        select_orchestration(database, fixture, fixture.jobs[2], 10_006, 20_006).await?;
    let replay_request = selection.request.clone();
    let initial = activation_authority(&selection.consumed)?;
    let chain = renew_activation_chain(database, &selection.selected, &initial).await?;
    let current = activation_authority(&chain.current)?;
    let new_request = RenewLogicalJobActivation::new(current.claim().clone(), NEW_RENEWAL_MILLIS)?;
    assert_eq!(
        database
            .store()
            .quarantine_logical_job_orchestration(QuarantineLogicalJobOrchestration::new(
                chain.current.clone(),
                LogicalWorkQuarantineKind::ObjectEvidence,
            ))
            .await?,
        LogicalWorkQuarantineOutcome::Quarantined
    );
    assert_ordinary_activation_quarantine(
        database,
        selection.selected.selection_id(),
        "object_evidence",
    )
    .await?;
    assert_eq!(
        database
            .store()
            .renew_logical_job_activation(chain.first_request)
            .await?,
        chain.first_ack
    );
    assert!(matches!(
        consume_orchestration(database, selection.selected).await,
        Err(LogicalWorkSelectionStoreError::SelectionQuarantined)
    ));
    assert!(matches!(
        database
            .store()
            .renew_logical_job_activation(new_request)
            .await,
        Err(LogicalActivationStoreError::ClaimRejected)
    ));
    assert!(matches!(
        database
            .store()
            .claim_next_logical_job_orchestration(replay_request.clone())
            .await?,
        LogicalJobOrchestrationSelectionOutcome::Quarantined
    ));
    corrupt_activation_quarantine_selection_and_assert_replay_corrupt(
        database,
        fixture.jobs[2],
        replay_request,
    )
    .await?;
    Ok(())
}

async fn exercise_quarantined_materialization(
    database: &TestDatabase,
    fixture: &Fixture,
    prepared: &PreparedInstance,
) -> TestResult {
    let selection = select_materialization(
        database,
        fixture,
        fixture.jobs[3],
        prepared.activated.id(),
        10_009,
        20_009,
    )
    .await?;
    let replay_request = selection.request.clone();
    let initial = selection.consumed.authority().clone();
    let chain = renew_materialization_chain(database, &selection.selected, &initial).await?;
    let new_request = RenewLogicalInstanceMaterialization::new(
        chain.current.authority().claim().clone(),
        NEW_RENEWAL_MILLIS,
    )?;
    assert_eq!(
        database
            .store()
            .quarantine_logical_instance_materialization(
                QuarantineLogicalInstanceMaterialization::new(
                    chain.current.clone(),
                    LogicalWorkQuarantineKind::RelationalEvidence,
                ),
            )
            .await?,
        LogicalWorkQuarantineOutcome::Quarantined
    );
    assert_ordinary_materialization_quarantine(
        database,
        selection.selected.selection_id(),
        "relational_evidence",
    )
    .await?;
    assert_eq!(
        database
            .store()
            .renew_logical_instance_materialization(chain.first_request)
            .await?,
        chain.first_ack
    );
    assert!(matches!(
        consume_materialization(database, selection.selected).await,
        Err(LogicalWorkSelectionStoreError::SelectionQuarantined)
    ));
    assert!(matches!(
        database
            .store()
            .renew_logical_instance_materialization(new_request)
            .await,
        Err(LogicalMaterializationStoreError::ClaimRejected)
    ));
    assert!(matches!(
        database
            .store()
            .claim_next_logical_instance_materialization(replay_request.clone())
            .await?,
        LogicalInstanceMaterializationSelectionOutcome::Quarantined
    ));
    corrupt_materialization_quarantine_authority_and_assert_replay_corrupt(
        database,
        prepared.activated.id(),
        replay_request,
    )
    .await?;
    Ok(())
}

async fn assert_ordinary_activation_quarantine(
    database: &TestDatabase,
    selection_id: LogicalWorkSelectionId,
    expected_failure: &str,
) -> TestResult {
    let (failure, outcome, exact): (String, String, bool) = sqlx::query_as(
        r"
        SELECT quarantine.failure_kind, selection.outcome,
               (quarantine.selection_owner_id,
                quarantine.selection_requested_at_ms,
                quarantine.selection_duration_ms,
                quarantine.selection_claimed_at_ms,
                quarantine.selection_expires_at_ms,
                quarantine.tenant_id, quarantine.run_id,
                quarantine.invocation_id, quarantine.logical_job_id,
                quarantine.selection_generation, quarantine.authority_kind,
                quarantine.authority_digest)
               IS NOT DISTINCT FROM
               (selection.owner_id, selection.requested_at_ms,
                selection.duration_ms, selection.claimed_at_ms,
                selection.expires_at_ms, selection.tenant_id,
                selection.run_id, selection.invocation_id,
                selection.logical_job_id, selection.generation,
                selection.authority_kind, selection.authority_digest)
        FROM logical_workflow_activation_work_quarantines AS quarantine
        JOIN logical_workflow_activation_work_selections AS selection
          ON selection.selection_id = quarantine.selection_id
        WHERE quarantine.selection_id = $1
        ",
    )
    .bind(selection_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(failure, expected_failure);
    assert_eq!(outcome, "claimed");
    assert!(exact);
    Ok(())
}

async fn assert_ordinary_materialization_quarantine(
    database: &TestDatabase,
    selection_id: LogicalWorkSelectionId,
    expected_failure: &str,
) -> TestResult {
    let (failure, outcome, exact): (String, String, bool) = sqlx::query_as(
        r"
        SELECT quarantine.failure_kind, selection.outcome,
               (quarantine.selection_owner_id,
                quarantine.selection_requested_at_ms,
                quarantine.selection_duration_ms,
                quarantine.selection_claimed_at_ms,
                quarantine.selection_expires_at_ms,
                quarantine.tenant_id, quarantine.run_id,
                quarantine.invocation_id, quarantine.logical_job_id,
                quarantine.instance_id, quarantine.selection_generation,
                quarantine.authority_digest)
               IS NOT DISTINCT FROM
               (selection.owner_id, selection.requested_at_ms,
                selection.duration_ms, selection.claimed_at_ms,
                selection.expires_at_ms, selection.tenant_id,
                selection.run_id, selection.invocation_id,
                selection.logical_job_id, selection.instance_id,
                selection.generation, selection.authority_digest)
        FROM logical_workflow_materialization_work_quarantines AS quarantine
        JOIN logical_workflow_materialization_work_selections AS selection
          ON selection.selection_id = quarantine.selection_id
        WHERE quarantine.selection_id = $1
        ",
    )
    .bind(selection_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(failure, expected_failure);
    assert_eq!(outcome, "claimed");
    assert!(exact);
    Ok(())
}

async fn delete_activation_quarantine_and_assert_replay_corrupt(
    database: &TestDatabase,
    logical_job_id: LogicalWorkflowJobId,
    request: ClaimNextLogicalJobOrchestration,
) -> TestResult {
    let mut corruption = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *corruption)
        .await?;
    let rows = sqlx::query(
        "DELETE FROM logical_workflow_activation_work_quarantines WHERE logical_job_id = $1",
    )
    .bind(logical_job_id.as_uuid())
    .execute(&mut *corruption)
    .await?
    .rows_affected();
    assert_eq!(rows, 1);
    corruption.commit().await?;
    assert_corrupt_selection_replay(
        &database
            .store()
            .claim_next_logical_job_orchestration(request)
            .await,
    );
    Ok(())
}

async fn corrupt_materialization_quarantine_failure_and_assert_replay_corrupt(
    database: &TestDatabase,
    instance_id: automata_ci_store::LogicalWorkflowInstanceId,
    request: ClaimNextLogicalInstanceMaterialization,
) -> TestResult {
    let mut corruption = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *corruption)
        .await?;
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_materialization_work_quarantines
        SET failure_kind = 'relational_evidence'
        WHERE instance_id = $1
        ",
    )
    .bind(instance_id.as_uuid())
    .execute(&mut *corruption)
    .await?
    .rows_affected();
    assert_eq!(rows, 1);
    corruption.commit().await?;
    assert_corrupt_selection_replay(
        &database
            .store()
            .claim_next_logical_instance_materialization(request)
            .await,
    );
    Ok(())
}

async fn corrupt_activation_quarantine_selection_and_assert_replay_corrupt(
    database: &TestDatabase,
    logical_job_id: LogicalWorkflowJobId,
    request: ClaimNextLogicalJobOrchestration,
) -> TestResult {
    let mut corruption = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *corruption)
        .await?;
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_activation_work_quarantines
        SET selection_owner_id = $2
        WHERE logical_job_id = $1
        ",
    )
    .bind(logical_job_id.as_uuid())
    .bind(Uuid::from_u128(0xdeca_fbad_0001))
    .execute(&mut *corruption)
    .await?
    .rows_affected();
    assert_eq!(rows, 1);
    corruption.commit().await?;
    assert_corrupt_selection_replay(
        &database
            .store()
            .claim_next_logical_job_orchestration(request)
            .await,
    );
    Ok(())
}

async fn corrupt_materialization_quarantine_authority_and_assert_replay_corrupt(
    database: &TestDatabase,
    instance_id: automata_ci_store::LogicalWorkflowInstanceId,
    request: ClaimNextLogicalInstanceMaterialization,
) -> TestResult {
    let mut corruption = database.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *corruption)
        .await?;
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_materialization_work_quarantines
        SET authority_owner_id = $2
        WHERE instance_id = $1
        ",
    )
    .bind(instance_id.as_uuid())
    .bind(Uuid::from_u128(0xdeca_fbad_0002))
    .execute(&mut *corruption)
    .await?
    .rows_affected();
    assert_eq!(rows, 1);
    corruption.commit().await?;
    assert_corrupt_selection_replay(
        &database
            .store()
            .claim_next_logical_instance_materialization(request)
            .await,
    );
    Ok(())
}

fn assert_corrupt_selection_replay<T>(result: &Result<T, LogicalWorkSelectionStoreError>) {
    assert!(matches!(
        result,
        Err(LogicalWorkSelectionStoreError::Store(
            StoreError::CorruptData(_)
        ))
    ));
}

async fn renew_preparation_chain(
    database: &TestDatabase,
    selected: &SelectedLogicalJobOrchestration,
    initial: &ClaimedLogicalActivationPreparation,
) -> TestResult<PreparationRenewalChain> {
    let first_request =
        RenewLogicalActivationPreparation::new(initial.claim().clone(), FIRST_RENEWAL_MILLIS)?;
    let first_ack = database
        .store()
        .renew_logical_activation_preparation(first_request.clone())
        .await?;
    let second_predecessor =
        preparation_authority(&consume_orchestration(database, selected.clone()).await?)?;
    assert_successor_matches_preparation(&first_ack, &second_predecessor);
    let second_request = RenewLogicalActivationPreparation::new(
        second_predecessor.claim().clone(),
        SECOND_RENEWAL_MILLIS,
    )?;
    let second_ack = database
        .store()
        .renew_logical_activation_preparation(second_request)
        .await?;
    assert_eq!(
        database
            .store()
            .renew_logical_activation_preparation(first_request.clone())
            .await?,
        first_ack
    );
    let current = consume_orchestration(database, selected.clone()).await?;
    assert_successor_matches_preparation(&second_ack, &preparation_authority(&current)?);
    reject_wrong_preparation_requests(database, initial).await?;
    Ok(PreparationRenewalChain {
        first_request,
        first_ack,
        current,
    })
}

async fn renew_activation_chain(
    database: &TestDatabase,
    selected: &SelectedLogicalJobOrchestration,
    initial: &ClaimedLogicalJobActivation,
) -> TestResult<ActivationRenewalChain> {
    let first_request =
        RenewLogicalJobActivation::new(initial.claim().clone(), FIRST_RENEWAL_MILLIS)?;
    let first_ack = database
        .store()
        .renew_logical_job_activation(first_request.clone())
        .await?;
    let second_predecessor =
        activation_authority(&consume_orchestration(database, selected.clone()).await?)?;
    assert_successor_matches_activation(&first_ack, &second_predecessor);
    let second_request =
        RenewLogicalJobActivation::new(second_predecessor.claim().clone(), SECOND_RENEWAL_MILLIS)?;
    let second_ack = database
        .store()
        .renew_logical_job_activation(second_request)
        .await?;
    assert_eq!(
        database
            .store()
            .renew_logical_job_activation(first_request.clone())
            .await?,
        first_ack
    );
    let current = consume_orchestration(database, selected.clone()).await?;
    assert_successor_matches_activation(&second_ack, &activation_authority(&current)?);
    reject_wrong_activation_requests(database, initial).await?;
    Ok(ActivationRenewalChain {
        first_request,
        first_ack,
        current,
    })
}

async fn renew_materialization_chain(
    database: &TestDatabase,
    selected: &SelectedLogicalInstanceMaterialization,
    initial: &ClaimedLogicalInstanceMaterialization,
) -> TestResult<MaterializationRenewalChain> {
    let first_request =
        RenewLogicalInstanceMaterialization::new(initial.claim().clone(), FIRST_RENEWAL_MILLIS)?;
    let first_ack = database
        .store()
        .renew_logical_instance_materialization(first_request.clone())
        .await?;
    let second_predecessor = consume_materialization(database, selected.clone()).await?;
    assert_successor_matches_materialization(&first_ack, second_predecessor.authority());
    let second_request = RenewLogicalInstanceMaterialization::new(
        second_predecessor.authority().claim().clone(),
        SECOND_RENEWAL_MILLIS,
    )?;
    let second_ack = database
        .store()
        .renew_logical_instance_materialization(second_request)
        .await?;
    assert_eq!(
        database
            .store()
            .renew_logical_instance_materialization(first_request.clone())
            .await?,
        first_ack
    );
    let current = consume_materialization(database, selected.clone()).await?;
    assert_successor_matches_materialization(&second_ack, current.authority());
    reject_wrong_materialization_requests(database, initial).await?;
    Ok(MaterializationRenewalChain {
        first_request,
        first_ack,
        current,
    })
}

async fn reject_wrong_preparation_requests(
    database: &TestDatabase,
    initial: &ClaimedLogicalActivationPreparation,
) -> TestResult {
    let wrong_duration =
        RenewLogicalActivationPreparation::new(initial.claim().clone(), FIRST_RENEWAL_MILLIS + 1)?;
    assert!(matches!(
        database
            .store()
            .renew_logical_activation_preparation(wrong_duration)
            .await,
        Err(LogicalActivationPreparationStoreError::ClaimRejected)
    ));
    let claim = initial.claim();
    let wrong_predecessor = LogicalActivationPreparationClaimFence::new_for_selection(
        claim.target().clone(),
        claim.owner(),
        claim.generation(),
        Sha256Digest::from_bytes([0xf1; 32]),
        claim.claimed_at(),
        claim.expires_at(),
        claim.selection_origin(),
    )?;
    assert!(matches!(
        database
            .store()
            .renew_logical_activation_preparation(RenewLogicalActivationPreparation::new(
                wrong_predecessor,
                FIRST_RENEWAL_MILLIS,
            )?)
            .await,
        Err(LogicalActivationPreparationStoreError::ClaimRejected)
    ));
    Ok(())
}

async fn reject_wrong_activation_requests(
    database: &TestDatabase,
    initial: &ClaimedLogicalJobActivation,
) -> TestResult {
    let wrong_duration =
        RenewLogicalJobActivation::new(initial.claim().clone(), FIRST_RENEWAL_MILLIS + 1)?;
    assert!(matches!(
        database
            .store()
            .renew_logical_job_activation(wrong_duration)
            .await,
        Err(LogicalActivationStoreError::ClaimRejected)
    ));
    let claim = initial.claim();
    let wrong_predecessor = LogicalActivationClaimFence::new_for_selection(
        claim.tenant().clone(),
        claim.run_id(),
        claim.invocation_id(),
        claim.logical_job_id(),
        claim.owner(),
        claim.runtime_policy().clone(),
        claim.generation(),
        Sha256Digest::from_bytes([0xf2; 32]),
        claim.claimed_at(),
        claim.expires_at(),
        claim.selection_origin(),
    )?;
    assert!(matches!(
        database
            .store()
            .renew_logical_job_activation(RenewLogicalJobActivation::new(
                wrong_predecessor,
                FIRST_RENEWAL_MILLIS,
            )?)
            .await,
        Err(LogicalActivationStoreError::ClaimRejected)
    ));
    Ok(())
}

async fn reject_wrong_materialization_requests(
    database: &TestDatabase,
    initial: &ClaimedLogicalInstanceMaterialization,
) -> TestResult {
    let wrong_duration = RenewLogicalInstanceMaterialization::new(
        initial.claim().clone(),
        FIRST_RENEWAL_MILLIS + 1,
    )?;
    assert!(matches!(
        database
            .store()
            .renew_logical_instance_materialization(wrong_duration)
            .await,
        Err(LogicalMaterializationStoreError::ClaimRejected)
    ));
    let claim = initial.claim();
    let wrong_predecessor = LogicalMaterializationClaimFence::new_for_selection(
        claim.target().clone(),
        claim.owner(),
        claim.generation(),
        Sha256Digest::from_bytes([0xf3; 32]),
        claim.runtime_policy().clone(),
        claim.expected_job_id(),
        claim.expected_attempt_id(),
        claim.claimed_at(),
        claim.expires_at(),
        claim.selection_origin(),
    )?;
    assert!(matches!(
        database
            .store()
            .renew_logical_instance_materialization(RenewLogicalInstanceMaterialization::new(
                wrong_predecessor,
                FIRST_RENEWAL_MILLIS,
            )?)
            .await,
        Err(LogicalMaterializationStoreError::ClaimRejected)
    ));
    Ok(())
}

fn assert_successor_matches_preparation(
    acknowledgement: &RenewedLogicalActivationPreparation,
    claimed: &ClaimedLogicalActivationPreparation,
) {
    assert_eq!(
        claimed.claim().generation(),
        acknowledgement.successor_generation()
    );
    assert_eq!(
        claimed.claim().claimed_at(),
        acknowledgement.successor_claimed_at()
    );
    assert_eq!(
        claimed.claim().expires_at(),
        acknowledgement.successor_expires_at()
    );
}

fn assert_successor_matches_activation(
    acknowledgement: &RenewedLogicalJobActivation,
    claimed: &ClaimedLogicalJobActivation,
) {
    assert_eq!(
        claimed.claim().generation(),
        acknowledgement.successor_generation()
    );
    assert_eq!(
        claimed.claim().claimed_at(),
        acknowledgement.successor_claimed_at()
    );
    assert_eq!(
        claimed.claim().expires_at(),
        acknowledgement.successor_expires_at()
    );
}

fn assert_successor_matches_materialization(
    acknowledgement: &RenewedLogicalInstanceMaterialization,
    claimed: &ClaimedLogicalInstanceMaterialization,
) {
    assert_eq!(
        claimed.claim().generation(),
        acknowledgement.successor_generation()
    );
    assert_eq!(
        claimed.claim().claimed_at(),
        acknowledgement.successor_claimed_at()
    );
    assert_eq!(
        claimed.claim().expires_at(),
        acknowledgement.successor_expires_at()
    );
}

fn preparation_authority(
    consumed: &ConsumedSelectedLogicalJobOrchestration,
) -> TestResult<ClaimedLogicalActivationPreparation> {
    match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => Ok(claimed.clone()),
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            Err(format!("expected preparation authority, got {authority:?}").into())
        }
    }
}

fn activation_authority(
    consumed: &ConsumedSelectedLogicalJobOrchestration,
) -> TestResult<ClaimedLogicalJobActivation> {
    match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => Ok(claimed.clone()),
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            Err(format!("expected activation authority, got {authority:?}").into())
        }
    }
}

async fn prepare_without_renewal(
    database: &TestDatabase,
    fixture: &Fixture,
    job: LogicalWorkflowJobId,
    identity: u128,
) -> TestResult {
    let selection =
        select_orchestration(database, fixture, job, identity, identity + 10_000).await?;
    let claimed = preparation_authority(&selection.consumed)?;
    bind_preparation(database, &claimed, &format!("setup-{identity}")).await?;
    Ok(())
}

async fn publish_without_renewal(
    database: &TestDatabase,
    fixture: &Fixture,
    job: LogicalWorkflowJobId,
    identity: u128,
) -> TestResult<PreparedInstance> {
    let selection =
        select_orchestration(database, fixture, job, identity, identity + 10_000).await?;
    let claimed = activation_authority(&selection.consumed)?;
    let prepared = prepared_instance(fixture, &claimed, &format!("setup-{identity}"));
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            claimed.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    Ok(prepared)
}

async fn bind_preparation(
    database: &TestDatabase,
    claimed: &ClaimedLogicalActivationPreparation,
    namespace: &str,
) -> TestResult {
    database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            claimed.descriptor().clone(),
            claimed.claim().clone(),
            claimed.descriptor().base_context().clone(),
            context_object(&format!("contexts/{namespace}/needs.pb"), 0x32),
            UnixMillis::new(database_now_ms(database).await?),
        )?)
        .await?;
    Ok(())
}

async fn select_orchestration(
    database: &TestDatabase,
    fixture: &Fixture,
    expected_job: LogicalWorkflowJobId,
    selection_id: u128,
    owner_id: u128,
) -> TestResult<OrchestrationSelection> {
    let request = ClaimNextLogicalJobOrchestration::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection_id))?,
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(owner_id))?,
        UnixMillis::new(database_now_ms(database).await?),
        INITIAL_SELECTION_MILLIS,
    )?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(request.clone())
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected orchestration selection, got {outcome:?}").into()),
    };
    assert_eq!(selected.target().run_id(), fixture.command.run_id());
    assert_eq!(selected.target().logical_job_id(), expected_job);
    let consumed = consume_orchestration(database, selected.clone()).await?;
    Ok(OrchestrationSelection {
        request,
        selected,
        consumed,
    })
}

async fn select_materialization(
    database: &TestDatabase,
    fixture: &Fixture,
    expected_job: LogicalWorkflowJobId,
    expected_instance: automata_ci_store::LogicalWorkflowInstanceId,
    selection_id: u128,
    owner_id: u128,
) -> TestResult<MaterializationSelection> {
    let request = ClaimNextLogicalInstanceMaterialization::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(selection_id))?,
        LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(owner_id))?,
        UnixMillis::new(database_now_ms(database).await?),
        INITIAL_SELECTION_MILLIS,
    )?;
    let selected = match database
        .store()
        .claim_next_logical_instance_materialization(request.clone())
        .await?
    {
        LogicalInstanceMaterializationSelectionOutcome::Selected(selected) => selected,
        outcome => {
            return Err(format!("expected materialization selection, got {outcome:?}").into());
        }
    };
    assert_eq!(selected.target().run_id(), fixture.command.run_id());
    assert_eq!(selected.target().logical_job_id(), expected_job);
    assert_eq!(selected.target().instance_id(), expected_instance);
    let consumed = consume_materialization(database, selected.clone()).await?;
    Ok(MaterializationSelection {
        request,
        selected,
        consumed,
    })
}

async fn consume_orchestration(
    database: &TestDatabase,
    selected: SelectedLogicalJobOrchestration,
) -> Result<ConsumedSelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError> {
    database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await
}

async fn consume_materialization(
    database: &TestDatabase,
    selected: SelectedLogicalInstanceMaterialization,
) -> Result<ConsumedSelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError> {
    database
        .store()
        .consume_selected_logical_instance_materialization(
            ConsumeSelectedLogicalInstanceMaterialization::new(selected),
        )
        .await
}

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Logical renewal ACK test tenant', 1, 1)
        ",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn fixture(
    database: &TestDatabase,
    tenant: &str,
    namespace: u128,
    eligible_job_index: usize,
) -> TestResult<Fixture> {
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
        GithubRepositoryName::new(format!("sample-owner/renewal-{namespace}"))?,
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(u64::try_from(namespace + 50)?)?,
        GithubServerServiceAppClientId::new(format!("Iv1.renewal-{namespace}"))?,
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
    let invocation_id = LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5))?;
    let jobs = [
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6))?,
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 7))?,
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 8))?,
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 9))?,
    ];
    let admitted_jobs = vec![AdmittedLogicalWorkflowJob::new(
        jobs[eligible_job_index],
        WorkflowJobKey::new(format!("renewal-{eligible_job_index}"))?,
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )?];
    let repository = AdmissionRepository::new(
        manifest.repository_id(),
        "github",
        github_repository.get().to_string(),
        "sample-owner",
        format!("renewal-{namespace}"),
    )?;
    let git_ref = "refs/heads/main";
    let head_sha = vec![9; 20];
    let trust_snapshot =
        crate::support::authenticated_github_trust_snapshot(&repository, git_ref, &head_sha)?;
    let command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!("renewal-{namespace}"))?,
        Sha256Digest::from_bytes([41; 32]),
        repository,
        workflow_id,
        ".ci/workflows/ci.yml",
        "Renewal ACK",
        git_ref,
        snapshot_id,
        admission_object(format!("renewal/{namespace}/source"), 1, "application/json"),
        admission_object(
            format!("renewal/{namespace}/plan-v1"),
            2,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(format!("renewal/{namespace}/event"), 3, "application/json"),
        head_sha,
        admitted_jobs,
        UnixMillis::new(database_now_ms(database).await?),
    )
    .trust_snapshot(trust_snapshot)
    .base_context(admission_object(
        format!("renewal/{namespace}/base-context"),
        4,
        "application/vnd.automata.job-runtime-context.protobuf",
    ))
    .build()?;
    Ok(Fixture {
        tenant: tenant.to_owned(),
        namespace,
        manifest,
        command,
        jobs,
    })
}

#[allow(clippy::too_many_lines)] // The fixture stages one complete authenticated delivery transaction.
async fn admit_authenticated_fixture(database: &TestDatabase, fixture: &mut Fixture) -> TestResult {
    let now = UnixMillis::new(database_now_ms(database).await?);
    let bootstrap =
        github_manifest_fixture::fixture_github_repository_bootstrap(fixture.manifest.clone(), now);
    database
        .store()
        .bootstrap_github_provider_repository(bootstrap.clone())
        .await?;
    crate::support::seed_fresh_github_workflow_permission_defaults(database, &bootstrap).await?;
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
                    format!("renewal-{}", fixture.namespace),
                )?,
                fixture.command.request_digest(),
                crate::support::authenticated_github_event_object(fixture.command.event())?,
                crate::support::provider_delivery_event_envelope(0x88),
                UnixMillis::new(database_now_ms(database).await?),
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
    builder = builder.trust_snapshot(command.trust_snapshot().clone());
    Ok(builder.build()?)
}

#[allow(clippy::too_many_lines)]
fn prepared_instance(
    fixture: &Fixture,
    claimed: &ClaimedLogicalJobActivation,
    namespace: &str,
) -> PreparedInstance {
    let matrix_digest = Sha256Digest::from_bytes([0x77; 32]);
    let identity = JobInstanceIdentity::new(claimed.logical_key().as_str(), 0, 1, matrix_digest)
        .expect("matrix identity");
    let empty = ContextValue::empty_object();
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
        ObjectKey::new(format!("contexts/{namespace}.json")).expect("runtime key"),
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
        "Renewal ACK job",
        RunnerRequirements::default(),
        identity.clone(),
        false,
        vec![step],
    )
    .with_authority_profile(JobAuthorityProfile::Standard);
    let execution = claimed.execution();
    let mut job_execution = JobExecutionContext::new(
        execution.workflow_name(),
        execution.git_ref(),
        format!("/runner/work/{namespace}"),
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
            "sample-owner/renewal",
            "0123456789abcdef",
            ".ci/workflows/ci.yml",
            "push",
        ),
        job_execution,
        job,
    );
    envelope.validate().expect("valid JobIR");
    let encoded = serde_json::to_vec(&envelope).expect("encoded JobIR");
    let activated = ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        format!("/runner/work/{namespace}"),
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new(format!("job-ir/{namespace}.json")).expect("JobIR key"),
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

fn admission_object(key: String, digest: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("object key"),
        768,
        media_type,
    )
    .expect("admission object")
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

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}
