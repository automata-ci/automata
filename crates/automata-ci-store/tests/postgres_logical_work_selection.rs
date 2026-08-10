#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use std::sync::Arc;

use automata_ci_core::{
    JobAuthorityProfile, RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AdmissionObject,
    AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, ClaimNextLogicalInstanceMaterialization,
    ClaimNextLogicalJobOrchestration, ClaimProviderDelivery, EnsureGithubServerServiceAuthority,
    GithubCheckHeadSha, GithubCheckName, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    LogicalActivationWorkerId, LogicalInstanceMaterializationSelectionOutcome,
    LogicalJobOrchestrationSelectionOutcome, LogicalMaterializationWorkerId,
    LogicalWorkSelectionId, LogicalWorkSelectionRepository as _, LogicalWorkSelectionStoreError,
    LogicalWorkflowAdmissionRepository as _, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS, ObjectKey,
    ProviderConnectionId, ProviderDeliveryClaimOwnerId, ProviderDeliveryIdentity,
    ProviderDeliveryRepository as _, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};
use uuid::Uuid;

use common::{TestDatabase, TestError, TestResult, run_with_database};

const MIGRATION_SQL: &str =
    include_str!("../migrations/0043_workflow_runtime_policy_and_selection.sql");

#[test]
fn migration_closes_reciprocal_quarantine_custody() {
    for required in [
        "workflow_plan_v2_activation_quarantine_selection_unique UNIQUE (selection_id)",
        "workflow_plan_v2_materialization_quarantine_selection_unique UNIQUE (selection_id)",
        "CREATE FUNCTION automata_require_final_activation_work_quarantine()",
        "CREATE FUNCTION automata_require_final_materialization_work_quarantine()",
        "WHEN NEW.failure_kind = 'generation_exhausted' THEN 'quarantined'",
        "workflow_plan_v2_activation_quarantine_selection_closure",
        "workflow_plan_v2_materialization_quarantine_selection_closure",
        "DEFERRABLE INITIALLY DEFERRED",
        "CREATE FUNCTION automata_require_pristine_logical_job_admission()",
        "workflow_plan_v2_jobs_activation_admission_pristine",
        "CREATE TRIGGER workflow_plan_v2_jobs_00_activation_admission",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "0043 lost work-selection quarantine closure: {required}"
        );
    }
}

struct AuthenticatedFixture {
    namespace: u128,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    job: LogicalWorkflowJobId,
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn authenticated_admission_is_pristine_and_direct_authority_inserts_fail() -> TestResult {
    run_with_database(|database| async move {
        let fixture = admit_authenticated_fixture(&database, 790_000).await?;
        let pristine: bool = sqlx::query_scalar(
            r"
            SELECT state = 'pending' AND activation_fence = 0
                   AND activation_owner_id IS NULL
                   AND activation_claimed_at_ms IS NULL
                   AND activation_expires_at_ms IS NULL
                   AND activation_input_digest IS NULL
                   AND authority_profile IS NULL
                   AND activation_origin_selection_id IS NULL
            FROM workflow_plan_v2_jobs
            WHERE id = $1
            ",
        )
        .bind(fixture.job.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(pristine);

        assert_nonpristine_job_inserts_rejected(&database, fixture.job).await?;

        let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(0x790_100))?;
        let outcome = database
            .store()
            .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
                selection_id,
                LogicalActivationWorkerId::from_uuid(Uuid::from_u128(0x790_101))?,
                UnixMillis::new(database_now_ms(&database).await?),
                MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
            )?)
            .await?;
        let LogicalJobOrchestrationSelectionOutcome::Selected(selected) = outcome else {
            return Err(
                format!("authenticated admitted job was not selectable: {outcome:?}").into(),
            );
        };
        assert_eq!(selected.target().run_id(), fixture.command.run_id());
        assert_eq!(selected.target().logical_job_id(), fixture.job);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One concurrency scenario asserts both queue families symmetrically.
async fn empty_queues_replay_exactly_and_never_leave_selecting_receipts() -> TestResult {
    run_with_database(|database| async move {
        assert_quarantine_catalog(&database).await?;
        let now = database_now_ms(&database).await?;
        let activation_owner = LogicalActivationWorkerId::from_uuid(Uuid::from_u128(0x1100))?;
        let materialization_owner =
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(0x1200))?;
        let activation_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(0x1300))?;
        let materialization_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(0x1400))?;
        let activation = ClaimNextLogicalJobOrchestration::new(
            activation_id,
            activation_owner,
            UnixMillis::new(now),
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
        )?;
        let materialization = ClaimNextLogicalInstanceMaterialization::new(
            materialization_id,
            materialization_owner,
            UnixMillis::new(now),
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
        )?;

        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_orchestration(activation.clone())
                .await?,
            LogicalJobOrchestrationSelectionOutcome::Idle
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_orchestration(activation.clone())
                .await?,
            LogicalJobOrchestrationSelectionOutcome::Idle
        ));
        let conflicting_activation = ClaimNextLogicalJobOrchestration::new(
            activation_id,
            activation_owner,
            UnixMillis::new(now),
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS + 1,
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_job_orchestration(conflicting_activation)
                .await,
            Err(LogicalWorkSelectionStoreError::SelectionConflict)
        ));

        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(materialization.clone())
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Idle
        ));
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(materialization.clone())
                .await?,
            LogicalInstanceMaterializationSelectionOutcome::Idle
        ));
        let conflicting_materialization = ClaimNextLogicalInstanceMaterialization::new(
            materialization_id,
            materialization_owner,
            UnixMillis::new(now),
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS + 1,
        )?;
        assert!(matches!(
            database
                .store()
                .claim_next_logical_instance_materialization(conflicting_materialization)
                .await,
            Err(LogicalWorkSelectionStoreError::SelectionConflict)
        ));

        let mut activation_tasks = Vec::new();
        let mut materialization_tasks = Vec::new();
        for index in 0_u128..8 {
            let activation_database = Arc::clone(&database);
            activation_tasks.push(tokio::spawn(async move {
                let request = ClaimNextLogicalJobOrchestration::new(
                    LogicalWorkSelectionId::from_uuid(Uuid::from_u128(0x2000 + index))?,
                    activation_owner,
                    UnixMillis::new(now),
                    MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
                )?;
                let outcome = activation_database
                    .store()
                    .claim_next_logical_job_orchestration(request)
                    .await?;
                Ok::<_, TestError>(outcome)
            }));

            let materialization_database = Arc::clone(&database);
            materialization_tasks.push(tokio::spawn(async move {
                let request = ClaimNextLogicalInstanceMaterialization::new(
                    LogicalWorkSelectionId::from_uuid(Uuid::from_u128(0x3000 + index))?,
                    materialization_owner,
                    UnixMillis::new(now),
                    MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
                )?;
                let outcome = materialization_database
                    .store()
                    .claim_next_logical_instance_materialization(request)
                    .await?;
                Ok::<_, TestError>(outcome)
            }));
        }
        for task in activation_tasks {
            assert!(matches!(
                task.await??,
                LogicalJobOrchestrationSelectionOutcome::Idle
            ));
        }
        for task in materialization_tasks {
            assert!(matches!(
                task.await??,
                LogicalInstanceMaterializationSelectionOutcome::Idle
            ));
        }

        let selecting: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*)::BIGINT
                 FROM workflow_plan_v2_activation_work_selections
                 WHERE outcome = 'selecting'),
                (SELECT count(*)::BIGINT
                 FROM workflow_plan_v2_materialization_work_selections
                 WHERE outcome = 'selecting')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(selecting, (0, 0));
        Ok(())
    })
    .await
}

async fn assert_nonpristine_job_inserts_rejected(
    database: &TestDatabase,
    admitted_job: LogicalWorkflowJobId,
) -> TestResult {
    let pending_error = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_jobs (
            id, run_id, invocation_id, logical_key, source_order,
            execution_kind, state, activation_fence,
            activation_owner_id, activation_claimed_at_ms,
            activation_expires_at_ms, activation_input_digest,
            authority_profile, activation_origin_selection_id,
            created_at_ms, updated_at_ms,
            runtime_policy_revision, runtime_policy_digest
        )
        SELECT $2, run_id, invocation_id, 'forged-pending', source_order + 1,
               execution_kind, 'pending', 1,
               NULL, NULL, NULL, NULL, NULL, NULL,
               created_at_ms, updated_at_ms,
               runtime_policy_revision, runtime_policy_digest
        FROM workflow_plan_v2_jobs
        WHERE id = $1
        ",
    )
    .bind(admitted_job.as_uuid())
    .bind(Uuid::from_u128(0x790_200))
    .execute(database.pool())
    .await
    .expect_err("pending admission may not smuggle a nonzero activation fence");
    assert_database_constraint(
        &pending_error,
        "workflow_plan_v2_jobs_activation_admission_pristine",
    );

    let now = database_now_ms(database).await?;
    let activating_error = sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_jobs (
            id, run_id, invocation_id, logical_key, source_order,
            execution_kind, state, activation_fence,
            activation_owner_id, activation_claimed_at_ms,
            activation_expires_at_ms, activation_input_digest,
            authority_profile, activation_origin_selection_id,
            created_at_ms, updated_at_ms,
            runtime_policy_revision, runtime_policy_digest
        )
        SELECT $2, run_id, invocation_id, 'forged-activating', source_order + 2,
               execution_kind, 'activating', 1,
               $3, $4, $5, $6, 'standard', $7,
               created_at_ms, $4,
               runtime_policy_revision, runtime_policy_digest
        FROM workflow_plan_v2_jobs
        WHERE id = $1
        ",
    )
    .bind(admitted_job.as_uuid())
    .bind(Uuid::from_u128(0x790_201))
    .bind(Uuid::from_u128(0x790_202))
    .bind(now)
    .bind(now + 60_000)
    .bind([0x91_u8; 32].as_slice())
    .bind(Uuid::from_u128(0x790_203))
    .execute(database.pool())
    .await
    .expect_err("admission may not insert already-active authority");
    assert_database_constraint(
        &activating_error,
        "workflow_plan_v2_jobs_activation_admission_pristine",
    );

    let forged_rows: i64 = sqlx::query_scalar(
        "SELECT count(*)::BIGINT FROM workflow_plan_v2_jobs WHERE id IN ($1,$2)",
    )
    .bind(Uuid::from_u128(0x790_200))
    .bind(Uuid::from_u128(0x790_201))
    .fetch_one(database.pool())
    .await?;
    assert_eq!(forged_rows, 0);
    Ok(())
}

fn assert_database_constraint(error: &sqlx::Error, expected: &str) {
    let database = error
        .as_database_error()
        .expect("direct-DML refusal is a PostgreSQL error");
    assert_eq!(database.code().as_deref(), Some("23514"));
    assert_eq!(database.constraint(), Some(expected));
}

#[allow(clippy::too_many_lines)] // Authenticated admission is one immutable provider-evidence chain.
async fn admit_authenticated_fixture(
    database: &TestDatabase,
    namespace: u128,
) -> TestResult<AuthenticatedFixture> {
    let tenant_name = format!("selection-admission-{namespace}");
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Logical selection admission guard tenant', 1, 1)
        ",
    )
    .bind(&tenant_name)
    .execute(database.pool())
    .await?;

    let tenant = TenantScope::from_authenticated_tenant_id(&tenant_name)?;
    let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(namespace + 20))?;
    let installation = ProviderInstallationId::new(u64::try_from(namespace + 30)?)?;
    let github_repository = ProviderRepositoryId::new(u64::try_from(namespace + 40)?)?;
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new(
        tenant.clone(),
        connection,
        installation,
        github_repository,
        GithubRepositoryName::new(format!("sample-owner/admission-{namespace}"))?,
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(u64::try_from(namespace + 50)?)?,
        GithubServerServiceAppClientId::new(format!("Iv1.admission-{namespace}"))?,
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
    let job = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6))?;
    let now = UnixMillis::new(database_now_ms(database).await?);
    let command = AdmitLogicalWorkflowRun::builder(
        tenant,
        WorkflowAdmissionIdempotency::provider_delivery(format!("admission-{namespace}"))?,
        Sha256Digest::from_bytes([41; 32]),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            github_repository.get().to_string(),
            "sample-owner",
            format!("admission-{namespace}"),
        )?,
        WorkflowId::from_uuid(Uuid::from_u128(namespace + 2)),
        ".github/workflows/ci.yml",
        "Admission guard",
        "refs/heads/main",
        WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3)),
        admission_object(
            format!("admission/{namespace}/source"),
            1,
            "application/json",
        ),
        admission_object(
            format!("admission/{namespace}/plan-v2"),
            2,
            "application/vnd.automata.workflow-plan+json",
        ),
        RunId::from_uuid(Uuid::from_u128(namespace + 4)),
        1,
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5))?,
        "push",
        admission_object(
            format!("admission/{namespace}/event"),
            3,
            "application/json",
        ),
        vec![9; 20],
        vec![AdmittedLogicalWorkflowJob::new(
            job,
            WorkflowJobKey::new("build")?,
            0,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        )?],
        now,
    )
    .build()?;
    let mut fixture = AuthenticatedFixture {
        namespace,
        manifest,
        command,
        job,
    };
    authenticate_fixture(database, &mut fixture).await?;
    Ok(fixture)
}

async fn authenticate_fixture(
    database: &TestDatabase,
    fixture: &mut AuthenticatedFixture,
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
                    format!("admission-{}", fixture.namespace),
                )?,
                fixture.command.request_digest(),
                fixture.command.event().clone(),
                UnixMillis::new(database_now_ms(database).await?),
            )?,
            ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace + 60)?)?,
            ProviderRepositoryOwnerId::new(u64::try_from(fixture.namespace + 60)?)?,
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
    fixture.command = logical_command_at(&fixture.command, claimed.claimed_at())?;
    database
        .store()
        .admit_authenticated_github_delivery(
            fixture.command.clone(),
            AuthenticatedGithubDeliveryClaim::new(
                claimed.claim(),
                claimed.attempt(),
                claimed.claimed_at(),
                claimed.expires_at(),
            )?,
            fixture.command.admitted_at(),
        )
        .await?;
    Ok(())
}

fn logical_command_at(
    command: &AdmitLogicalWorkflowRun,
    admitted_at: UnixMillis,
) -> TestResult<AdmitLogicalWorkflowRun> {
    Ok(AdmitLogicalWorkflowRun::builder(
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
    )
    .build()?)
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

async fn assert_quarantine_catalog(database: &TestDatabase) -> TestResult {
    let unique_constraints: Vec<String> = sqlx::query_scalar(
        r"
        SELECT catalog_constraint.conname
        FROM pg_constraint AS catalog_constraint
        JOIN pg_namespace AS catalog_namespace
          ON catalog_namespace.oid = catalog_constraint.connamespace
        WHERE catalog_namespace.nspname = current_schema()
          AND catalog_constraint.conname IN (
            'workflow_plan_v2_activation_quarantine_selection_unique',
            'workflow_plan_v2_materialization_quarantine_selection_unique'
          )
          AND catalog_constraint.contype = 'u'
        ORDER BY catalog_constraint.conname
        ",
    )
    .fetch_all(database.pool())
    .await?;
    assert_eq!(unique_constraints.len(), 2);

    let deferred_triggers: Vec<(String, bool, bool)> = sqlx::query_as(
        r"
        SELECT catalog_trigger.tgname, catalog_trigger.tgdeferrable,
               catalog_trigger.tginitdeferred
        FROM pg_trigger AS catalog_trigger
        JOIN pg_class AS catalog_relation
          ON catalog_relation.oid = catalog_trigger.tgrelid
        JOIN pg_namespace AS catalog_namespace
          ON catalog_namespace.oid = catalog_relation.relnamespace
        WHERE catalog_namespace.nspname = current_schema()
          AND catalog_trigger.tgname IN (
            'workflow_plan_v2_activation_quarantine_selection_closure',
            'workflow_plan_v2_materialization_quarantine_selection_closure'
          )
        ORDER BY catalog_trigger.tgname
        ",
    )
    .fetch_all(database.pool())
    .await?;
    assert_eq!(deferred_triggers.len(), 2);
    assert!(
        deferred_triggers
            .iter()
            .all(|(_, deferrable, initially_deferred)| *deferrable && *initially_deferred)
    );
    Ok(())
}

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?,
    )
}
