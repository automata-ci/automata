mod common;
mod github_manifest_fixture;

use std::time::Duration;

use automata_ci_core::{
    Architecture, JobAuthorityProfile, JobId, JobIrVersion, JobLifecycle, OperatingSystem,
    OperationId, RunId, RunnerCapabilities, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AcknowledgeRunnerCommands,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    ArtifactReservationKind, ArtifactState, AuthenticatedGithubDeliveryClaim,
    BindLogicalActivationPreparation, BuiltinSecretCleanupStatus, ClaimNextLogicalJobOrchestration,
    ClaimProviderDelivery, CommandCursor, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, ControlPlaneStateRepository as _,
    ControlPlaneStateSnapshot, ControlPlaneStateSnapshotRequest, DocumentSchema,
    EnqueueRunnerCommand, EnsureGithubServerServiceAuthority, GithubCheckHeadSha, GithubCheckName,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    JobAttemptCounts, LeaseState, LogicalActivationPreparationStore as _,
    LogicalActivationWorkerId, LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionId,
    LogicalWorkSelectionRepository as _, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind, ObjectKey,
    ProviderConnectionId, ProviderDeliveryClaimOwnerId, ProviderDeliveryIdentity,
    ProviderDeliveryRepository as _, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    RunnerCommandOutbox as _, RunnerCommandPayload, RunnerDesiredState, RunnerGeneration,
    RunnerObservedState, RunnerOperationKind, RunnerSessionFence, RunnerSessionState, SessionEpoch,
    TenantScope, WORKFLOW_ADMISSION_EPOCH, WorkflowAdmissionIdempotency, WorkflowRunStatus,
    WorkflowSnapshotId,
};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

#[derive(Debug)]
struct MetricsSeed {
    tenant_id: String,
    repository_id: Uuid,
    run_id: Uuid,
    queued_job: JobId,
    fence: RunnerSessionFence,
}

#[derive(Debug)]
struct MetricsWorkflowSeed {
    tenant_id: String,
    repository_id: Uuid,
    workflow_id: Uuid,
    snapshot_id: Uuid,
    run_id: Uuid,
    queued_job: JobId,
}

#[derive(Clone, Copy, Debug)]
struct LogicalMetricsObservation {
    snapshot_time: UnixMillis,
    pending_since: UnixMillis,
    expired_since: UnixMillis,
}

struct LogicalMetricsFixture {
    suffix: String,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    active_job: LogicalWorkflowJobId,
    expired_job: LogicalWorkflowJobId,
    pending_job: LogicalWorkflowJobId,
}

#[derive(Debug)]
struct BuiltinSecretCleanupSeed {
    principal_id: Uuid,
    secret_id: Uuid,
    secret_version_id: Uuid,
    mutation_id: Uuid,
    session_id: Uuid,
    create_request_id: String,
    provider_subject: String,
    token_hash: [u8; 32],
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn postgres_snapshot_maps_every_durable_aggregate_and_acknowledged_outbox_state() -> TestResult
{
    run_with_database(|database| async move {
        let seed = seed_metrics_state(&database).await?;
        let logical = insert_logical_metrics_state(&database, &seed).await?;
        let active_job = copy_job(&database, seed.queued_job, "active").await?;
        let near_job = copy_job(&database, seed.queued_job, "near").await?;
        let expired_job = copy_job(&database, seed.queued_job, "expired").await?;
        let eligible_job = copy_job(&database, seed.queued_job, "eligible").await?;

        let queued_attempt = insert_queued_attempt(&database, seed.queued_job, 100).await?;
        insert_queued_attempt(&database, eligible_job, 150).await?;
        let active_attempt = insert_leased_attempt(
            &database,
            active_job,
            seed.fence,
            1,
            logical.snapshot_time.get() + 120_000,
        )
        .await?;
        let near_attempt = insert_leased_attempt(
            &database,
            near_job,
            seed.fence,
            2,
            logical.snapshot_time.get() + 30_000,
        )
        .await?;
        insert_leased_attempt(
            &database,
            expired_job,
            seed.fence,
            3,
            logical.snapshot_time.get() - 10_000,
        )
        .await?;
        insert_cancellation_intents(&database, queued_attempt, active_attempt, near_attempt)
            .await?;
        insert_artifact_state(&database, &seed, active_job, active_attempt).await?;
        insert_builtin_secret_cleanup_state(&database, &seed.tenant_id).await?;

        let command = database
            .store()
            .enqueue_command(EnqueueRunnerCommand::new(
                seed.fence,
                OperationId::new(),
                RunnerOperationKind::new("automata.metrics-test.v1")?,
                RunnerCommandPayload::new(DocumentSchema::new(1)?, b"bounded".to_vec())?,
                UnixMillis::new(500),
            ))
            .await?;

        let request =
            ControlPlaneStateSnapshotRequest::new(logical.snapshot_time, Duration::from_mins(1))?;
        let snapshot = database
            .store()
            .control_plane_state_snapshot(request)
            .await?;
        assert_initial_snapshot(&snapshot, logical);

        let pool = database.store().database_pool_snapshot()?;
        assert_eq!(pool.maximum(), 16);
        assert_eq!(pool.open(), pool.idle() + pool.in_use());

        database
            .store()
            .acknowledge_commands(AcknowledgeRunnerCommands::new(
                seed.fence,
                CommandCursor::through(command.sequence()),
                UnixMillis::new(100_001),
            ))
            .await?;
        sqlx::query(
            r"
            UPDATE attempt_cancellation_intents
            SET acknowledged_at_ms = 500
            WHERE acknowledged_at_ms IS NULL
            ",
        )
        .execute(database.pool())
        .await?;
        let acknowledged = database
            .store()
            .control_plane_state_snapshot(request)
            .await?;
        assert_eq!(acknowledged.pending_commands(), 0);
        assert_eq!(acknowledged.pending_commands_oldest_at(), None);
        assert_eq!(acknowledged.pending_cancellation_intents(), 0);
        assert_eq!(acknowledged.pending_cancellation_intents_oldest_at(), None);
        Ok(())
    })
    .await
}

fn assert_initial_snapshot(
    snapshot: &ControlPlaneStateSnapshot,
    logical: LogicalMetricsObservation,
) {
    assert_logical_snapshot(snapshot, logical);
    assert_runner_snapshot(snapshot);
    assert_cleanup_and_artifact_snapshot(snapshot);
}

fn assert_logical_snapshot(
    snapshot: &ControlPlaneStateSnapshot,
    logical: LogicalMetricsObservation,
) {
    assert_eq!(snapshot.workflow_runs().get(WorkflowRunStatus::Queued), 2);
    assert_eq!(
        snapshot
            .workflow_plan_v2_runs()
            .get(automata_ci_store::WorkflowPlanV2RunState::Active),
        1
    );
    assert_eq!(
        snapshot
            .logical_jobs()
            .get(automata_ci_store::LogicalJobState::Pending),
        1
    );
    assert_eq!(
        snapshot
            .logical_jobs()
            .get(automata_ci_store::LogicalJobState::Activating),
        2
    );
    assert_eq!(
        snapshot
            .logical_activations()
            .oldest_at(automata_ci_store::LogicalActivationState::Pending),
        Some(logical.pending_since)
    );
    assert_eq!(
        snapshot
            .logical_activations()
            .get(automata_ci_store::LogicalActivationState::Expired),
        1
    );
    assert_eq!(
        snapshot
            .logical_activations()
            .oldest_at(automata_ci_store::LogicalActivationState::Expired),
        Some(logical.expired_since)
    );
    assert_eq!(snapshot.activation_publications(), 0);
    assert_eq!(snapshot.materialized_instances(), 0);
    assert_eq!(snapshot.job_attempts().get(JobLifecycle::Queued), 2);
    assert_eq!(snapshot.job_attempts().get(JobLifecycle::Running), 3);
    assert_eq!(snapshot.queue_depth(), 2);
    assert_eq!(snapshot.queue_oldest_at(), Some(UnixMillis::new(100)));
    assert_eq!(snapshot.eligible_queue_depth(), 1);
    assert_eq!(
        snapshot.eligible_queue_oldest_at(),
        Some(UnixMillis::new(150))
    );
}

fn assert_runner_snapshot(snapshot: &ControlPlaneStateSnapshot) {
    assert_eq!(snapshot.capacity().candidates().len(), 1);
    assert_eq!(snapshot.capacity().runners().len(), 1);
    assert_eq!(snapshot.capacity().runners()[0].occupied_slots().len(), 3);
    assert_eq!(snapshot.leases().get(LeaseState::Active), 1);
    assert_eq!(snapshot.leases().get(LeaseState::NearExpiry), 1);
    assert_eq!(snapshot.leases().get(LeaseState::Expired), 1);
    assert_eq!(
        snapshot
            .runners()
            .get(RunnerObservedState::Online, RunnerDesiredState::Active),
        1
    );
    assert_eq!(snapshot.runner_sessions().get(RunnerSessionState::Live), 1);
    assert_eq!(snapshot.pending_commands(), 1);
    assert_eq!(
        snapshot.pending_commands_oldest_at(),
        Some(UnixMillis::new(500))
    );
    assert_eq!(snapshot.pending_cancellation_intents(), 2);
    assert_eq!(
        snapshot.pending_cancellation_intents_oldest_at(),
        Some(UnixMillis::new(300))
    );
}

fn assert_cleanup_and_artifact_snapshot(snapshot: &ControlPlaneStateSnapshot) {
    let cleanup = snapshot.builtin_secret_cleanup();
    for (status, oldest_created_at) in [
        (BuiltinSecretCleanupStatus::Pending, 600),
        (BuiltinSecretCleanupStatus::InProgress, 700),
        (BuiltinSecretCleanupStatus::DeadLetter, 800),
    ] {
        assert_eq!(cleanup.get(status), 1);
        assert_eq!(
            cleanup.oldest_created_at(status),
            Some(UnixMillis::new(oldest_created_at))
        );
    }
    assert_eq!(snapshot.artifacts().get(ArtifactState::PendingUpload), 1);
    assert_eq!(
        snapshot.artifacts().get(ArtifactState::PublicationReserved),
        1
    );
    assert_eq!(snapshot.artifacts().get(ArtifactState::Finalized), 1);
    assert_eq!(
        snapshot
            .artifact_reservations()
            .get(ArtifactReservationKind::Block),
        2
    );
    assert_eq!(
        snapshot
            .artifact_reservations()
            .oldest_at(ArtifactReservationKind::Block),
        Some(UnixMillis::new(10_000))
    );
    assert_eq!(
        snapshot
            .artifact_reservations()
            .get(ArtifactReservationKind::Manifest),
        1
    );
    assert_eq!(
        snapshot
            .artifact_reservations()
            .oldest_at(ArtifactReservationKind::Manifest),
        Some(UnixMillis::new(20_000))
    );
}

async fn seed_metrics_state(database: &TestDatabase) -> TestResult<MetricsSeed> {
    let seed = MetricsWorkflowSeed {
        tenant_id: format!("metrics-tenant-{}", Uuid::new_v4().simple()),
        repository_id: Uuid::new_v4(),
        workflow_id: Uuid::new_v4(),
        snapshot_id: Uuid::new_v4(),
        run_id: Uuid::new_v4(),
        queued_job: JobId::new(),
    };
    insert_metrics_workflow(database, &seed).await?;
    let fence = insert_metrics_runner(database, &seed.tenant_id).await?;
    Ok(MetricsSeed {
        tenant_id: seed.tenant_id,
        repository_id: seed.repository_id,
        run_id: seed.run_id,
        queued_job: seed.queued_job,
        fence,
    })
}

async fn insert_builtin_secret_cleanup_state(
    database: &TestDatabase,
    tenant_id: &str,
) -> TestResult {
    let seed = generate_builtin_secret_cleanup_seed();
    insert_secret_cleanup_actor(database, tenant_id, &seed).await?;
    insert_secret_cleanup_intent(database, tenant_id, &seed).await?;
    insert_staged_secret_version(database, tenant_id, &seed).await?;
    insert_secret_cleanup_outbox(database, tenant_id, &seed).await?;
    Ok(())
}

fn generate_builtin_secret_cleanup_seed() -> BuiltinSecretCleanupSeed {
    let principal_id = Uuid::new_v4();
    let secret_id = Uuid::new_v4();
    let secret_version_id = Uuid::new_v4();
    let mutation_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let create_request_id = format!("secret-version:{mutation_id}");
    let provider_subject = format!("metrics-secret-{}", principal_id.simple());
    let mut token_hash = [0_u8; 32];
    token_hash[..16].copy_from_slice(session_id.as_bytes());
    token_hash[16..].copy_from_slice(session_id.as_bytes());
    BuiltinSecretCleanupSeed {
        principal_id,
        secret_id,
        secret_version_id,
        mutation_id,
        session_id,
        create_request_id,
        provider_subject,
        token_hash,
    }
}

async fn insert_secret_cleanup_actor(
    database: &TestDatabase,
    tenant_id: &str,
    seed: &BuiltinSecretCleanupSeed,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO human_principals (
            id, display_name, created_at_ms, updated_at_ms
        ) VALUES ($1, 'Metrics secret actor', 100, 100)
        ",
    )
    .bind(seed.principal_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id, provider_id, provider_subject, provider_login,
            normalized_login, first_authenticated_at_ms,
            last_authenticated_at_ms, last_observed_at_ms,
            created_at_ms, updated_at_ms
        ) VALUES (
            $1, 'github', $2, $2, $2, 100, 100, 100, 100, 100
        )
        ",
    )
    .bind(seed.principal_id)
    .bind(&seed.provider_subject)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id, principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 100, 100)
        ",
    )
    .bind(tenant_id)
    .bind(seed.principal_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id, tenant_id, principal_id, provider_id, provider_subject,
            session_kind, audience, token_hash, token_hash_key_id,
            authorization_revision, issued_at_ms, last_seen_at_ms,
            idle_expires_at_ms, expires_at_ms
        ) VALUES (
            $1, $2, $3, 'github', $4, 'browser', 'automata.web',
            $5, 'metrics-session-v1', 1, 100, 100, 740000, 750000
        )
        ",
    )
    .bind(seed.session_id)
    .bind(tenant_id)
    .bind(seed.principal_id)
    .bind(&seed.provider_subject)
    .bind(seed.token_hash.as_slice())
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn insert_secret_cleanup_intent(
    database: &TestDatabase,
    tenant_id: &str,
    seed: &BuiltinSecretCleanupSeed,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO secrets (
            tenant_id, id, canonical_name, scope_kind, provider_id,
            created_by_principal_id, updated_by_principal_id,
            created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, 'METRICS_SECRET', 'tenant', 'builtin',
            $3, $3, 100, 100
        )
        ",
    )
    .bind(tenant_id)
    .bind(seed.secret_id)
    .bind(seed.principal_id)
    .execute(database.pool())
    .await?;
    let mut recovery = database.pool().begin().await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_mutations (
            tenant_id, mutation_id, secret_id, scope_kind,
            canonical_name, provider_id, mutation_kind,
            reserved_secret_revision, reserved_version_number,
            confirmation_deadline_ms, provider_create_request_id,
            reserved_by_principal_id, reserved_by_session_id,
            reserved_authorization_revision, reserved_at_ms
        ) VALUES (
            $1, $2, $3, 'tenant', 'METRICS_SECRET', 'builtin', 'create',
            1, 1, 600100, $4, $5, $6, 1, 100
        )
        ",
    )
    .bind(tenant_id)
    .bind(seed.mutation_id)
    .bind(seed.secret_id)
    .bind(&seed.create_request_id)
    .bind(seed.principal_id)
    .bind(seed.session_id)
    .execute(&mut *recovery)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_mutation_recovery_outbox (
            operation_id, tenant_id, mutation_id,
            next_attempt_at_ms, created_at_ms
        ) VALUES (
            automata_secret_mutation_recovery_operation_id($1, $2),
            $1, $2, 600100, 100
        )
        ",
    )
    .bind(tenant_id)
    .bind(seed.mutation_id)
    .execute(&mut *recovery)
    .await?;
    recovery.commit().await?;
    Ok(())
}

async fn insert_staged_secret_version(
    database: &TestDatabase,
    tenant_id: &str,
    seed: &BuiltinSecretCleanupSeed,
) -> TestResult {
    let mut staging = database.pool().begin().await?;
    sqlx::query(
        r"
        INSERT INTO secret_versions (
            tenant_id, id, secret_id, version_number, provider_id,
            create_request_id, storage_kind, created_by_principal_id,
            created_at_ms
        ) VALUES (
            $1, $2, $3, 1, 'builtin', $4,
            'built_in_ciphertext', $5, 100
        )
        ",
    )
    .bind(tenant_id)
    .bind(seed.secret_version_id)
    .bind(seed.secret_id)
    .bind(&seed.create_request_id)
    .bind(seed.principal_id)
    .execute(&mut *staging)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_lifecycle (
            tenant_id, secret_version_id, secret_id, version_number,
            provider_id, mutation_id, status, revision,
            changed_by_principal_id, changed_at_ms
        ) VALUES (
            $1, $2, $3, 1, 'builtin', $4, 'staged', 1, $5, 100
        )
        ",
    )
    .bind(tenant_id)
    .bind(seed.secret_version_id)
    .bind(seed.secret_id)
    .bind(seed.mutation_id)
    .bind(seed.principal_id)
    .execute(&mut *staging)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_custody_key_canaries (
            wrapping_key_id, canary_generation, canary_schema,
            ciphertext, nonce, wrapped_data_key, envelope_schema,
            created_at_ms
        ) VALUES ('metrics-key-v1', 1, 1, $1, $2, $3, 1, 100)
        ",
    )
    .bind([7_u8; 52].as_slice())
    .bind([8_u8; 12].as_slice())
    .bind([9_u8; 48].as_slice())
    .execute(&mut *staging)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_envelopes (
            tenant_id, secret_version_id, secret_id, version_number,
            storage_kind, envelope_generation, ciphertext, nonce,
            wrapped_data_key, wrapping_key_id, envelope_schema, created_at_ms
        ) VALUES (
            $1, $2, $3, 1, 'built_in_ciphertext', 1,
            $4, $5, $6, 'metrics-key-v1', 1, 100
        )
        ",
    )
    .bind(tenant_id)
    .bind(seed.secret_version_id)
    .bind(seed.secret_id)
    .bind([1_u8].as_slice())
    .bind([2_u8; 12].as_slice())
    .bind([3_u8].as_slice())
    .execute(&mut *staging)
    .await?;
    sqlx::query(
        r"
        INSERT INTO secret_version_envelope_heads (
            tenant_id, secret_version_id, envelope_generation,
            revision, updated_at_ms
        ) VALUES ($1, $2, 1, 1, 100)
        ",
    )
    .bind(tenant_id)
    .bind(seed.secret_version_id)
    .execute(&mut *staging)
    .await?;
    staging.commit().await?;
    Ok(())
}

async fn insert_secret_cleanup_outbox(
    database: &TestDatabase,
    tenant_id: &str,
    seed: &BuiltinSecretCleanupSeed,
) -> TestResult {
    let pending = Uuid::new_v4();
    let in_progress = Uuid::new_v4();
    let dead_letter = Uuid::new_v4();
    let completed = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO secret_cleanup_outbox (
            operation_id, tenant_id, provider_id, cleanup_kind,
            secret_id, secret_version_id, version_number,
            next_attempt_at_ms, created_at_ms
        ) VALUES
            ($1, $5, 'builtin', 'destroy_secret_version', $6, $7, 1, 600, 600),
            ($2, $5, 'builtin', 'destroy_secret_version', $6, $7, 1, 700, 700),
            ($3, $5, 'builtin', 'destroy_secret_version', $6, $7, 1, 800, 800),
            ($4, $5, 'builtin', 'destroy_secret_version', $6, $7, 1, 900, 900)
        ",
    )
    .bind(pending)
    .bind(in_progress)
    .bind(dead_letter)
    .bind(completed)
    .bind(tenant_id)
    .bind(seed.secret_id)
    .bind(seed.secret_version_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        UPDATE secret_cleanup_outbox
        SET status = 'in_progress', attempts = 1, claim_generation = 1,
            locked_by = 'metrics-test', locked_at_ms = next_attempt_at_ms
        WHERE operation_id IN ($1, $2, $3)
        ",
    )
    .bind(in_progress)
    .bind(dead_letter)
    .bind(completed)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        UPDATE secret_cleanup_outbox
        SET status = 'dead_letter', next_attempt_at_ms = locked_at_ms + 1,
            locked_by = NULL, locked_at_ms = NULL,
            last_failure_kind = 'unavailable'
        WHERE operation_id = $1
        ",
    )
    .bind(dead_letter)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        UPDATE secret_cleanup_outbox
        SET status = 'completed', locked_by = NULL, locked_at_ms = NULL,
            completed_at_ms = 901
        WHERE operation_id = $1
        ",
    )
    .bind(completed)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn insert_logical_metrics_state(
    database: &TestDatabase,
    seed: &MetricsSeed,
) -> TestResult<LogicalMetricsObservation> {
    let mut fixture = build_logical_metrics_fixture(database, seed).await?;
    admit_logical_metrics_fixture(database, &mut fixture).await?;
    assert_logical_admission_evidence(database, &fixture.manifest, &fixture.command).await?;
    activate_logical_metrics_run(
        database,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
    )
    .await?;

    let worker = LogicalActivationWorkerId::from_uuid(Uuid::new_v4())?;
    prepare_logical_metrics_job(database, worker, fixture.active_job, &fixture.suffix).await?;
    prepare_logical_metrics_job(database, worker, fixture.expired_job, &fixture.suffix).await?;
    prepare_logical_metrics_job(database, worker, fixture.pending_job, &fixture.suffix).await?;
    let active = select_logical_metrics_job(database, worker, 120_000).await?;
    assert_eq!(active.target().logical_job_id(), fixture.active_job);
    assert_eq!(
        active.authority_kind(),
        automata_ci_store::LogicalJobOrchestrationAuthorityKind::Activation
    );
    let expired = select_logical_metrics_job(database, worker, 2_000).await?;
    assert_eq!(expired.target().logical_job_id(), fixture.expired_job);
    assert_eq!(
        expired.authority_kind(),
        automata_ci_store::LogicalJobOrchestrationAuthorityKind::Activation
    );
    wait_until_database_after(database, expired.expires_at().get()).await?;

    let pending_since: i64 =
        sqlx::query_scalar("SELECT created_at_ms FROM workflow_plan_v2_jobs WHERE id = $1")
            .bind(fixture.pending_job.as_uuid())
            .fetch_one(database.pool())
            .await?;
    Ok(LogicalMetricsObservation {
        snapshot_time: UnixMillis::new(database_now_ms(database).await?),
        pending_since: UnixMillis::new(pending_since),
        expired_since: expired.expires_at(),
    })
}

async fn build_logical_metrics_fixture(
    database: &TestDatabase,
    seed: &MetricsSeed,
) -> TestResult<LogicalMetricsFixture> {
    let suffix = Uuid::new_v4().simple().to_string();
    let tenant = TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?;
    let provider_repository_id = ProviderRepositoryId::new(9_100_001)?;
    let repository_name = GithubRepositoryName::new(format!("automata/metrics-{suffix}"))?;
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new(
        tenant.clone(),
        ProviderConnectionId::from_uuid(Uuid::new_v4())?,
        ProviderInstallationId::new(9_100_002)?,
        provider_repository_id,
        repository_name.clone(),
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(9_100_003)?,
        GithubServerServiceAppClientId::new(format!("Iv1.metrics-{suffix}"))?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([23; 32]),
        GithubServerServiceRevision::new(1)?,
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([24; 32]))?,
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
    let run_id = RunId::from_uuid(Uuid::new_v4());
    let invocation_id = LogicalWorkflowInvocationId::from_uuid(Uuid::new_v4())?;
    let active_job = LogicalWorkflowJobId::from_uuid(Uuid::new_v4())?;
    let expired_job = LogicalWorkflowJobId::from_uuid(Uuid::new_v4())?;
    let pending_job = LogicalWorkflowJobId::from_uuid(Uuid::new_v4())?;
    let delivery_key = format!("metrics-logical-{suffix}");
    let admitted_at = UnixMillis::new(database_now_ms(database).await?);
    let command = AdmitLogicalWorkflowRun::builder(
        tenant,
        WorkflowAdmissionIdempotency::provider_delivery(delivery_key.clone())?,
        Sha256Digest::from_bytes([14; 32]),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            provider_repository_id.get().to_string(),
            "automata",
            format!("metrics-{suffix}"),
        )?,
        WorkflowId::from_uuid(Uuid::new_v4()),
        ".github/workflows/ci.yml",
        "Metrics",
        "refs/heads/main",
        WorkflowSnapshotId::from_uuid(Uuid::new_v4()),
        logical_metrics_object(
            format!("metrics/{suffix}/workflow.yml"),
            17,
            "application/yaml",
        ),
        logical_metrics_object(
            format!("metrics/{suffix}/plan-v2.json"),
            19,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        logical_metrics_object(
            format!("metrics/{suffix}/event.json"),
            18,
            "application/json",
        ),
        vec![20; 20],
        vec![
            logical_metrics_job(active_job, "active", 0),
            logical_metrics_job(expired_job, "expired", 1),
            logical_metrics_job(pending_job, "pending", 2),
        ],
        admitted_at,
    )
    .actor("metrics-observer")
    .build()?;
    Ok(LogicalMetricsFixture {
        suffix,
        manifest,
        command,
        active_job,
        expired_job,
        pending_job,
    })
}

async fn admit_logical_metrics_fixture(
    database: &TestDatabase,
    fixture: &mut LogicalMetricsFixture,
) -> TestResult {
    let manifest = &fixture.manifest;
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                UnixMillis::new(database_now_ms(database).await?),
            ),
        )
        .await?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            GithubServerServiceAuthorityIdentity::new(
                manifest.tenant().clone(),
                GithubServerServiceAuthorityId::from_uuid(Uuid::new_v4())?,
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
                Sha256Digest::from_bytes([25; 32]),
            )?,
            UnixMillis::new(database_now_ms(database).await?),
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
                    format!("metrics-logical-{}", fixture.suffix),
                )?,
                fixture.command.request_digest(),
                fixture.command.event().clone(),
                accepted_at,
            )?,
            ProviderRepositoryOwnerId::new(9_100_004)?,
            ProviderRepositoryOwnerId::new(9_100_004)?,
            GithubCheckHeadSha::new([20; 20])?,
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
        )?)
        .await?;
    let claim_observed_at = database_now_ms(database).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(claim_observed_at),
            UnixMillis::new(claim_observed_at + 60_000),
        )?)
        .await?
        .ok_or("accepted metrics delivery was not claimable")?;
    assert_eq!(claimed.claim().delivery_id(), accepted.delivery_id());
    fixture.command = logical_metrics_command_at(&fixture.command, claimed.claimed_at())?;
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

fn logical_metrics_job(
    id: LogicalWorkflowJobId,
    key: &str,
    source_order: u16,
) -> AdmittedLogicalWorkflowJob {
    AdmittedLogicalWorkflowJob::new(
        id,
        WorkflowJobKey::new(key).expect("logical metrics job key"),
        source_order,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("logical metrics job")
}

fn logical_metrics_object(key: String, digest: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("logical metrics object key"),
        768,
        media_type,
    )
    .expect("logical metrics admission object")
}

fn logical_metrics_command_at(
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
    .actor(command.actor().unwrap_or_default())
    .build()?)
}

async fn assert_logical_admission_evidence(
    database: &TestDatabase,
    manifest: &GithubProviderManifest,
    command: &AdmitLogicalWorkflowRun,
) -> TestResult {
    let evidence: (i64, Vec<u8>, i64, i64) = sqlx::query_as(
        r"
        SELECT pin.policy_revision, pin.policy_digest,
               pin.pinned_at_ms, subject.admitted_at_ms
        FROM github_workflow_run_subject_evidence AS subject
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.provider_delivery_id = subject.provider_delivery_id
         AND delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
        JOIN workflow_plan_v2_runtime_policy_pins AS pin
          ON pin.run_id = subject.run_id
         AND pin.tenant_id = subject.tenant_id
         AND pin.repository_id = subject.repository_id
        JOIN workflow_admission_receipts AS receipt
          ON receipt.run_id = subject.run_id
         AND receipt.repository_id = subject.repository_id
         AND receipt.committed_at_ms = subject.admitted_at_ms
        WHERE subject.run_id = $1
        ",
    )
    .bind(command.run_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        evidence.0,
        i64::try_from(manifest.runtime_policy_revision().get())?
    );
    assert_eq!(
        evidence.1.as_slice(),
        manifest.runtime_policy_digest().as_bytes().as_slice()
    );
    assert_eq!(evidence.2, command.admitted_at().get());
    assert_eq!(evidence.3, command.admitted_at().get());
    Ok(())
}

async fn activate_logical_metrics_run(
    database: &TestDatabase,
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
) -> TestResult {
    let marker_rows = sqlx::query(
        r"
        WITH stamp AS (
            SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
        )
        UPDATE workflow_plan_v2_runs
        SET state = 'active', revision = revision + 1,
            updated_at_ms = stamp.now_ms
        FROM stamp
        WHERE run_id = $1 AND state = 'pending'
        ",
    )
    .bind(run_id.as_uuid())
    .execute(database.pool())
    .await?
    .rows_affected();
    let invocation_rows = sqlx::query(
        r"
        WITH stamp AS (
            SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
        )
        UPDATE workflow_plan_v2_invocations
        SET state = 'active', revision = revision + 1,
            updated_at_ms = stamp.now_ms
        FROM stamp
        WHERE run_id = $1 AND id = $2 AND state = 'pending'
        ",
    )
    .bind(run_id.as_uuid())
    .bind(invocation_id.as_uuid())
    .execute(database.pool())
    .await?
    .rows_affected();
    assert_eq!((marker_rows, invocation_rows), (1, 1));
    Ok(())
}

async fn select_logical_metrics_job(
    database: &TestDatabase,
    worker: LogicalActivationWorkerId,
    duration_ms: i64,
) -> TestResult<automata_ci_store::SelectedLogicalJobOrchestration> {
    let observed_at = UnixMillis::new(database_now_ms(database).await?);
    match database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
            worker,
            observed_at,
            duration_ms,
        )?)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => Ok(selected),
        outcome => Err(format!("expected logical metrics selection, got {outcome:?}").into()),
    }
}

async fn prepare_logical_metrics_job(
    database: &TestDatabase,
    worker: LogicalActivationWorkerId,
    expected_job: LogicalWorkflowJobId,
    suffix: &str,
) -> TestResult {
    let selected = select_logical_metrics_job(database, worker, 60_000).await?;
    assert_eq!(selected.target().logical_job_id(), expected_job);
    let consumed = database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?;
    let claimed = match consumed.authority() {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            return Err(format!("expected logical metrics preparation, got {authority:?}").into());
        }
    };
    let job_id = expected_job.as_uuid().simple();
    database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            claimed.descriptor().clone(),
            claimed.claim().clone(),
            logical_metrics_object(
                format!("metrics/{suffix}/{job_id}/base.pb"),
                31,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            logical_metrics_object(
                format!("metrics/{suffix}/{job_id}/needs.pb"),
                32,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            UnixMillis::new(database_now_ms(database).await?),
        )?)
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

async fn wait_until_database_after(database: &TestDatabase, target_ms: i64) -> TestResult {
    match tokio::time::timeout(Duration::from_secs(10), async {
        while database_now_ms(database).await? <= target_ms {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err("database clock did not advance past logical lease expiry".into()),
    }
}

async fn insert_metrics_workflow(
    database: &TestDatabase,
    seed: &MetricsWorkflowSeed,
) -> TestResult {
    let requirements = serde_json::to_value(RunnerRequirements::default())?;

    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Metrics test tenant', 1, 1)
        ",
    )
    .bind(&seed.tenant_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'test', $3, 'automata', 'metrics-test', 1, 1)
        ",
    )
    .bind(seed.repository_id)
    .bind(&seed.tenant_id)
    .bind(seed.repository_id.to_string())
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, '.github/workflows/metrics.yml', 1, 1)
        ",
    )
    .bind(seed.workflow_id)
    .bind(seed.repository_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key,
            source_size_bytes, source_media_type, frontend_schema,
            admission_epoch, created_at_ms
        ) VALUES (
            $1, $2, $3, 'metrics/workflow', 128, 'application/yaml', 1, $4, 1
        )
        ",
    )
    .bind(seed.snapshot_id)
    .bind(seed.workflow_id)
    .bind(vec![7_u8; 32])
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, event_name,
            event_object_key, event_digest, event_size_bytes, event_media_type,
            plan_digest, plan_object_key, plan_size_bytes, plan_media_type,
            plan_schema, head_sha, status, admission_epoch, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, $3, $4, 1, 'push', 'metrics/event', $5, 128,
            'application/json', $6, 'metrics/plan', 128,
            'application/vnd.automata.workflow-plan.protobuf', 2,
            $7, 'queued', $8, 1, 1
        )
        ",
    )
    .bind(seed.run_id)
    .bind(seed.repository_id)
    .bind(seed.workflow_id)
    .bind(seed.snapshot_id)
    .bind(vec![8_u8; 32])
    .bind(vec![13_u8; 32])
    .bind(vec![9_u8; 20])
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        ) VALUES (
            $1, $2, 'queued', 'Queued', $3,
            'metrics/job-ir', $4::jsonb, $5, $6, 128, 1
        )
        ",
    )
    .bind(seed.queued_job.as_uuid())
    .bind(seed.run_id)
    .bind(vec![11_u8; 32])
    .bind(requirements)
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .bind(i32::from(JobIrVersion::current().get()))
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn insert_metrics_runner(
    database: &TestDatabase,
    tenant_id: &str,
) -> TestResult<RunnerSessionFence> {
    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let capabilities = serde_json::to_value(RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    ))?;
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots, status,
            desired_state, generation, session_epoch, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, 'metrics-runner', 'metrics-runner', $3::jsonb, 4, 'online',
            'active', 1, 1, 1, 1
        )
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(tenant_id)
    .bind(&capabilities)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO runner_sessions (
            id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
            connected_at_ms, heartbeat_at_ms, runner_generation, session_epoch,
            last_command_sequence, acknowledged_command_sequence
        ) VALUES ($1, $2, 4, $3, $4::jsonb, 2, 2, 1, 1, 0, 0)
        ",
    )
    .bind(session_id.as_uuid())
    .bind(runner_id.as_uuid())
    .bind(i32::from(JobIrVersion::current().get()))
    .bind(&capabilities)
    .execute(database.pool())
    .await?;
    Ok(RunnerSessionFence::new(
        session_id,
        runner_id,
        RunnerGeneration::new(1)?,
        SessionEpoch::new(1)?,
    ))
}

async fn copy_job(database: &TestDatabase, source: JobId, key: &str) -> TestResult<JobId> {
    let job = JobId::new();
    let inserted = sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        SELECT $1, run_id, $2, $2, job_ir_digest,
               job_ir_object_key, requirements, admission_epoch,
               job_ir_schema, job_ir_size_bytes, created_at_ms
        FROM jobs
        WHERE id = $3
        ",
    )
    .bind(job.as_uuid())
    .bind(key)
    .bind(source.as_uuid())
    .execute(database.pool())
    .await?;
    assert_eq!(inserted.rows_affected(), 1);
    Ok(job)
}

async fn insert_queued_attempt(
    database: &TestDatabase,
    job: JobId,
    queued_at_ms: i64,
) -> TestResult<Uuid> {
    let attempt_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, queued_at_ms, changed_at_ms
        ) VALUES ($1, $2, 1, 'queued', $3, $3)
        ",
    )
    .bind(attempt_id)
    .bind(job.as_uuid())
    .bind(queued_at_ms)
    .execute(database.pool())
    .await?;
    Ok(attempt_id)
}

async fn insert_leased_attempt(
    database: &TestDatabase,
    job: JobId,
    fence: automata_ci_store::RunnerSessionFence,
    slot: i32,
    expires_at_ms: i64,
) -> TestResult<Uuid> {
    let attempt_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token,
            lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
            queued_at_ms, changed_at_ms, runner_session_id,
            runner_session_epoch, runner_generation, runner_slot
        ) VALUES (
            $1, $2, 1, 'running', 1,
            $3, $4, 1000, $5,
            100, 2000, $6, $7, $8, $9
        )
        ",
    )
    .bind(attempt_id)
    .bind(job.as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(expires_at_ms)
    .bind(fence.session_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(slot)
    .execute(database.pool())
    .await?;
    Ok(attempt_id)
}

async fn insert_cancellation_intents(
    database: &TestDatabase,
    first_pending: Uuid,
    second_pending: Uuid,
    acknowledged: Uuid,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO attempt_cancellation_intents (
            attempt_id, operation_id, requested_by, requested_at_ms, acknowledged_at_ms
        ) VALUES
            ($1, $2, 'metrics-test', 300, NULL),
            ($3, $4, 'metrics-test', 400, NULL),
            ($5, $6, 'metrics-test', 100, 200)
        ",
    )
    .bind(first_pending)
    .bind(Uuid::new_v4())
    .bind(second_pending)
    .bind(Uuid::new_v4())
    .bind(acknowledged)
    .bind(Uuid::new_v4())
    .execute(database.pool())
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn insert_artifact_state(
    database: &TestDatabase,
    seed: &MetricsSeed,
    job_id: JobId,
    attempt_id: Uuid,
) -> TestResult {
    let pending_artifact: i64 = sqlx::query_scalar(
        r"
        INSERT INTO workflow_artifacts (
            upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
            fencing_token, name, protocol_version, mime_type, created_at_seconds
        ) VALUES ($1, $2, $3, $4, $5, $6, 1, 'pending', 7, 'application/octet-stream', 10)
        RETURNING id
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&seed.tenant_id)
    .bind(seed.repository_id)
    .bind(seed.run_id)
    .bind(job_id.as_uuid())
    .bind(attempt_id)
    .fetch_one(database.pool())
    .await?;

    sqlx::query(
        r"
        INSERT INTO workflow_artifacts (
            upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
            fencing_token, name, protocol_version, mime_type, state,
            content_digest, content_size_bytes, manifest_object_key,
            manifest_digest, manifest_size_bytes, manifest_media_type,
            created_at_seconds, manifest_state, manifest_reserved_at_seconds,
            finalization_generation, finalization_claimed_size_bytes,
            finalization_claim_expires_at_seconds, manifest_bytes
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 1, 'reserved', 7, 'application/octet-stream',
            'pending', $7, 0, 'metrics/manifest-reserved', $8, 1,
            'application/json', 10, 'reserved', 20, 1, 0, 100, $9
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&seed.tenant_id)
    .bind(seed.repository_id)
    .bind(seed.run_id)
    .bind(job_id.as_uuid())
    .bind(attempt_id)
    .bind(vec![21_u8; 32])
    .bind(vec![22_u8; 32])
    .bind(vec![b'm'])
    .execute(database.pool())
    .await?;

    sqlx::query(
        r"
        INSERT INTO workflow_artifacts (
            upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
            fencing_token, name, protocol_version, mime_type, state,
            content_digest, content_size_bytes, manifest_object_key,
            manifest_digest, manifest_size_bytes, manifest_media_type,
            created_at_seconds, finalized_at_seconds, manifest_state,
            manifest_reserved_at_seconds, finalization_generation,
            finalization_claimed_size_bytes, finalization_claim_expires_at_seconds,
            manifest_bytes
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 1, 'finalized', 7, 'application/octet-stream',
            'finalized', $7, 0, 'metrics/manifest-finalized', $8, 1,
            'application/json', 10, 40, 'ready', 30, 1, 0, 100, $9
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&seed.tenant_id)
    .bind(seed.repository_id)
    .bind(seed.run_id)
    .bind(job_id.as_uuid())
    .bind(attempt_id)
    .bind(vec![23_u8; 32])
    .bind(vec![24_u8; 32])
    .bind(vec![b'm'])
    .execute(database.pool())
    .await?;

    sqlx::query(
        r"
        INSERT INTO workflow_artifact_blocks (
            artifact_id, block_id, object_key, digest, size_bytes, media_type,
            staged_at_seconds, state, ready_at_seconds
        ) VALUES
            ($1, 'blk1', 'metrics/block-1', $2, 1, 'application/octet-stream', 10, 'reserved', NULL),
            ($1, 'blk2', 'metrics/block-2', $3, 1, 'application/octet-stream', 12, 'reserved', NULL),
            ($1, 'blk3', 'metrics/block-3', $4, 1, 'application/octet-stream', 5, 'ready', 5)
        ",
    )
    .bind(pending_artifact)
    .bind(vec![31_u8; 32])
    .bind(vec![32_u8; 32])
    .bind(vec![33_u8; 32])
    .execute(database.pool())
    .await?;
    Ok(())
}

#[test]
fn all_attempt_lifecycles_are_in_the_public_closed_domain() {
    assert_eq!(JobAttemptCounts::ALL.len(), 12);
}
