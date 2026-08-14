use crate::github_manifest_fixture;

use std::time::Duration;

use automata_ci_core::{OperationId, RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey};
use automata_ci_postgres::store::PostgresStore;
use automata_ci_schedule::CronExpression;
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    BeginGithubCheckRunCreate, BindGithubCheckRun, BindGithubCheckSuite,
    ClaimDueGithubScheduleFire, ClaimGithubCheckProjection, ClaimGithubScheduleDiscovery,
    ClaimedGithubScheduleFire, CompleteGithubCheckProjection, CompleteGithubScheduleFire,
    EnsureGithubServerServiceAuthority, GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE,
    GITHUB_SCHEDULE_SERVICE_ACTOR, GithubCheckDetailsTarget, GithubCheckName,
    GithubCheckProjectionAction, GithubCheckProjectionOutbox as _, GithubCheckProjectionWorkerId,
    GithubCheckRunBindingFence, GithubCheckRunId, GithubCheckSubjectKey, GithubCheckSuiteId,
    GithubProviderGitRef, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision,
    GithubProviderManifestStoreError, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryName, GithubScheduleArchive, GithubScheduleDiscoveryClaim,
    GithubScheduleFireConclusion, GithubScheduleRegistryEntry, GithubScheduleRegistryId,
    GithubScheduleRepository as _, GithubScheduleSourceAuthority, GithubScheduleStoreError,
    GithubScheduleWorkerId, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceAuthoritySelector,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubServerServiceScope,
    LogicalWorkflowAdmissionRepository as _, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS, ObjectKey, ProviderConnectionId,
    ProviderInstallationId, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, RegisterGithubScheduleRegistry,
    RegisterGithubScheduledCheckSubject, RetryGithubScheduleFire, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};
use github_manifest_fixture::{fixture_github_repository_bootstrap, fixture_github_runtime_policy};

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One proof crosses registry, fire, Check, and admission fences.
async fn registry_replay_claim_retry_completion_and_supersession_are_fenced() -> TestResult {
    run_with_database(|database| async move {
        let tenant = TenantScope::from_authenticated_tenant_id("neutral-schedule-test")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(0x5901))?;
        let manifest = fixture_private_github_manifest(tenant, connection);
        database
            .store()
            .bootstrap_github_provider_repository(fixture_github_repository_bootstrap(
                manifest.clone(),
                UnixMillis::new(1),
            ))
            .await?;
        assert_schedule_repository_scoping(database.pool()).await?;
        let configured_at = database_now(database.pool()).await?;
        let checks_identity = schedule_authority_identity(
            &manifest,
            Uuid::from_u128(0x5909),
            GithubServerServiceScope::ChecksWrite,
            [51; 32],
        )?;
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                checks_identity,
                configured_at,
            )?)
            .await?;
        let private_identity = schedule_authority_identity(
            &manifest,
            Uuid::from_u128(0x5910),
            GithubServerServiceScope::PrivateRepositorySourceRead,
            [52; 32],
        )?;
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                private_identity.clone(),
                configured_at,
            )?)
            .await?;
        let other_manifest = fixture_private_github_manifest_for_repository(
            manifest.tenant().clone(),
            ProviderConnectionId::from_uuid(Uuid::from_u128(0x59f1))?,
            203,
            "example/other-schedules",
        );
        database
            .store()
            .bootstrap_github_provider_repository(fixture_github_repository_bootstrap(
                other_manifest.clone(),
                UnixMillis::new(1),
            ))
            .await?;
        let cross_repository_identity = schedule_authority_identity(
            &other_manifest,
            Uuid::from_u128(0x59f2),
            GithubServerServiceScope::PrivateRepositorySourceRead,
            [53; 32],
        )?;
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                cross_repository_identity.clone(),
                configured_at,
            )?)
            .await?;
        let source_authority = GithubScheduleSourceAuthority::Private(
            GithubServerServiceAuthoritySelector::from_identity(&private_identity),
        );
        let discovery_worker =
            GithubScheduleWorkerId::from_uuid(Uuid::from_u128(0x59d1))?;
        let cross_repository_request = ClaimGithubScheduleDiscovery::new(
            GithubScheduleRegistryId::from_uuid(Uuid::from_u128(0x59f3))?,
            manifest.clone(),
            ProviderRepositoryOwnerId::new(303)?,
            GithubScheduleSourceAuthority::Private(
                GithubServerServiceAuthoritySelector::from_identity(&cross_repository_identity),
            ),
            discovery_worker,
            300_000,
        )?;
        assert!(matches!(
            database
                .store()
                .claim_github_schedule_discovery(cross_repository_request)
                .await,
            Err(GithubScheduleStoreError::Conflict)
        ));
        let first_claim = claim_discovery(
            database.store(),
            GithubScheduleRegistryId::from_uuid(Uuid::from_u128(0x5902))?,
            manifest.clone(),
            source_authority.clone(),
            discovery_worker,
        )
        .await?;
        let first = registry(
            first_claim,
            manifest.clone(),
            source_authority.clone(),
            "1111111111111111111111111111111111111111",
            [21; 32],
        )?;
        let created = database
            .store()
            .register_github_schedule_registry(first.clone())
            .await?;
        assert!(!created.is_replay());

        let replay_claim = claim_discovery(
            database.store(),
            GithubScheduleRegistryId::from_uuid(Uuid::from_u128(0x5903))?,
            manifest.clone(),
            source_authority.clone(),
            discovery_worker,
        )
        .await?;
        let replay_request = registry(
            replay_claim,
            manifest.clone(),
            source_authority.clone(),
            "1111111111111111111111111111111111111111",
            [21; 32],
        )?;
        let replay = database
            .store()
            .register_github_schedule_registry(replay_request)
            .await?;
        assert!(replay.is_replay());
        assert_eq!(replay.registry_id(), created.registry_id());
        let completed_claim_replay = claim_discovery(
            database.store(),
            GithubScheduleRegistryId::from_uuid(Uuid::from_u128(0x5903))?,
            manifest.clone(),
            source_authority.clone(),
            discovery_worker,
        )
        .await?;
        assert_eq!(completed_claim_replay, replay_claim);
        let completed_discovery_receipt = database
            .store()
            .register_github_schedule_registry(registry(
                completed_claim_replay,
                manifest.clone(),
                source_authority.clone(),
                "1111111111111111111111111111111111111111",
                [21; 32],
            )?)
            .await?;
        assert!(completed_discovery_receipt.is_replay());
        assert_eq!(completed_discovery_receipt.registry_id(), created.registry_id());

        let conflicting_archive = registry(
            first.discovery_claim(),
            manifest.clone(),
            source_authority.clone(),
            "1111111111111111111111111111111111111111",
            [22; 32],
        )?;
        assert!(matches!(
            database
                .store()
                .register_github_schedule_registry(conflicting_archive)
                .await,
            Err(GithubScheduleStoreError::Conflict)
        ));

        make_due(database.pool(), created.registry_id()).await?;
        let worker = GithubScheduleWorkerId::from_uuid(Uuid::from_u128(0x5905))?;
        let claim_request = ClaimDueGithubScheduleFire::new(worker, 60_000)?;
        let claimed = database
            .store()
            .claim_due_github_schedule_fire(claim_request)
            .await?
            .expect("due fire");
        assert_eq!(claimed.source_revision(), "1111111111111111111111111111111111111111");
        assert_eq!(claimed.entry().cron_expression(), "0/5 * * * *");
        assert_eq!(claimed.entry().timezone(), "UTC");
        let original_claim = claimed.claim();
        let renewed = database
            .store()
            .renew_github_schedule_fire(original_claim, 60_000)
            .await?;
        assert!(renewed.expires_at() >= original_claim.expires_at());
        assert!(matches!(
            database
                .store()
                .retry_github_schedule_fire(RetryGithubScheduleFire::new(
                    original_claim,
                    1_000,
                    "transient_source"
                )?)
                .await,
            Err(GithubScheduleStoreError::ClaimRejected)
        ));
        database
            .store()
            .retry_github_schedule_fire(RetryGithubScheduleFire::new(
                renewed,
                1,
                "transient_source",
            )?)
            .await?;
        let pending: (i64, i16, i64, i64) = sqlx::query_as(
            r"
            SELECT next_attempt_at_ms, attempt_count, claim_fence, updated_at_ms
              FROM github_schedule_fires
             WHERE fire_id = $1
            ",
        )
        .bind(renewed.fire_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let early_claim = sqlx::query(
            r"
            UPDATE github_schedule_fires
               SET state = 'claimed',
                   attempt_count = attempt_count + 1,
                   claim_fence = claim_fence + 1,
                   claim_owner_id = $2,
                   claimed_at_ms = next_attempt_at_ms - 1,
                   claim_expires_at_ms = next_attempt_at_ms + 59999,
                   updated_at_ms = next_attempt_at_ms - 1
             WHERE fire_id = $1
            ",
        )
        .bind(renewed.fire_id().as_uuid())
        .bind(Uuid::from_u128(0x59ee))
        .execute(database.pool())
        .await
        .expect_err("a pending fire cannot be claimed before its due instant");
        assert_constraint(&early_claim, "github_schedule_fire_transition_exact");
        assert_eq!(pending.1, 1);
        assert_eq!(pending.2, 1);
        assert!(pending.0 > pending.3);
        wait_until_database_at_or_after(database.pool(), pending.0).await?;
        let second = database
            .store()
            .claim_due_github_schedule_fire(claim_request)
            .await?
            .expect("retried fire");
        assert_eq!(second.claim().attempt(), 2);
        assert!(second.claim().fence() > renewed.fence());
        let excessive_lease = sqlx::query(
            r"
            UPDATE github_schedule_fires
               SET claim_expires_at_ms = updated_at_ms + 300001
             WHERE fire_id = $1
            ",
        )
        .bind(second.claim().fire_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("a direct renewal cannot exceed the durable lease ceiling");
        assert_constraint(&excessive_lease, "github_schedule_fire_transition_exact");
        let identity_tamper = sqlx::query(
            "UPDATE github_schedule_fires SET created_at_ms = created_at_ms + 1 WHERE fire_id = $1",
        )
        .bind(second.claim().fire_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("fire identity evidence is immutable while claimed");
        assert_constraint(&identity_tamper, "github_schedule_fire_transition_exact");
        let direct_terminal = sqlx::query(
            r"
            UPDATE github_schedule_fires
               SET state = 'failed', claim_owner_id = NULL,
                   claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                   failure_kind = 'direct_tamper'
             WHERE fire_id = $1
            ",
        )
        .bind(second.claim().fire_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("terminal state requires atomic attempt and runtime evidence");
        assert_constraint(
            &direct_terminal,
            "github_schedule_fire_terminal_evidence",
        );
        let check = database
            .store()
            .register_github_scheduled_check_subject(RegisterGithubScheduledCheckSubject::new(
                second.claim(),
            ))
            .await
            .expect("register scheduled Check");
        assert_eq!(
            database
                .store()
                .register_github_scheduled_check_subject(
                    RegisterGithubScheduledCheckSubject::new(second.claim())
                )
                .await
                .expect("replay scheduled Check"),
            check
        );
        let check_origin: (String, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT origin_kind, provider_delivery_id, schedule_fire_id
              FROM github_check_subjects
             WHERE id = $1
            ",
        )
        .bind(check.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(check_origin.0, "scheduled_fire");
        assert_eq!(check_origin.1, None);
        assert_eq!(check_origin.2, Some(second.claim().fire_id().as_uuid()));

        // Persist the irreversible provider-create cutoff before admission.
        // The later run link must not change the exact details target used to
        // reconcile that possibly-created Check Run.
        let check_worker =
            GithubCheckProjectionWorkerId::from_uuid(Uuid::from_u128(0x5907))?;
        let projection_now = database_now(database.pool()).await?;
        let ensure_suite = database
            .store()
            .claim_github_check_projection(ClaimGithubCheckProjection::new(
                connection,
                check_worker,
                projection_now,
                UnixMillis::new(projection_now.get() + 60_000),
            )?)
            .await?
            .expect("scheduled Check suite projection");
        assert_eq!(ensure_suite.claim().subject_id(), check.subject_id());
        assert_eq!(
            ensure_suite.action(),
            GithubCheckProjectionAction::EnsureSuite
        );
        assert_eq!(
            ensure_suite.details_target(),
            GithubCheckDetailsTarget::Repository
        );
        let suite_id = GithubCheckSuiteId::new(59_071)?;
        database
            .store()
            .bind_github_check_suite(BindGithubCheckSuite::new(
                ensure_suite.claim(),
                suite_id,
                ensure_suite.claimed_at(),
            )?)
            .await?;

        let create_now = database_now(database.pool()).await?;
        let prepare_create = database
            .store()
            .claim_github_check_projection(ClaimGithubCheckProjection::new(
                connection,
                check_worker,
                create_now,
                UnixMillis::new(create_now.get() + 25),
            )?)
            .await?
            .expect("scheduled Check create projection");
        assert_eq!(prepare_create.claim().subject_id(), check.subject_id());
        assert_eq!(
            prepare_create.action(),
            GithubCheckProjectionAction::PrepareRunCreate
        );
        assert_eq!(
            prepare_create.details_target(),
            GithubCheckDetailsTarget::Repository
        );
        let reconcile_not_before = UnixMillis::new(prepare_create.expires_at().get() + 1);
        database
            .store()
            .begin_github_check_run_create(BeginGithubCheckRunCreate::new(
                &prepare_create,
                prepare_create.claimed_at(),
                reconcile_not_before,
            )?)
            .await?;

        let admitted_at = database_now(database.pool()).await?;
        let command = scheduled_command(&manifest, &second, admitted_at)?;
        let admitted = database
            .store()
            .admit_scheduled_github_workflow(command.clone(), second.claim())
            .await?;
        assert!(!admitted.is_replay());
        assert_eq!(
            database
                .store()
                .admit_scheduled_github_workflow(command, second.claim())
                .await?
                .run_id(),
            admitted.run_id()
        );
        wait_until_database_at_or_after(database.pool(), reconcile_not_before.get()).await?;
        let reconcile_now = database_now(database.pool()).await?;
        let reconcile = database
            .store()
            .claim_github_check_projection(ClaimGithubCheckProjection::new(
                connection,
                check_worker,
                reconcile_now,
                UnixMillis::new(reconcile_now.get() + 60_000),
            )?)
            .await?
            .expect("scheduled Check create reconciliation");
        assert_eq!(reconcile.claim().subject_id(), check.subject_id());
        assert_eq!(
            reconcile.action(),
            GithubCheckProjectionAction::ReconcileRunCreate
        );
        assert_eq!(
            reconcile.details_target(),
            GithubCheckDetailsTarget::Repository
        );
        assert_eq!(
            reconcile.identity().schedule_fire_id(),
            Some(second.claim().fire_id())
        );
        assert_eq!(reconcile.identity().delivery_id(), None);
        let check_run_id = GithubCheckRunId::new(59_072)?;
        database
            .store()
            .bind_github_check_run(BindGithubCheckRun::new(
                GithubCheckRunBindingFence::Reconciliation(reconcile.claim()),
                suite_id,
                check_run_id,
                reconcile.claimed_at(),
            )?)
            .await?;
        let publish_now = database_now(database.pool()).await?;
        let publish = database
            .store()
            .claim_github_check_projection(ClaimGithubCheckProjection::new(
                connection,
                check_worker,
                publish_now,
                UnixMillis::new(publish_now.get() + 60_000),
            )?)
            .await?
            .expect("linked scheduled Check publication");
        assert_eq!(publish.claim().subject_id(), check.subject_id());
        assert_eq!(publish.action(), GithubCheckProjectionAction::Publish);
        assert_eq!(
            publish.details_target(),
            GithubCheckDetailsTarget::Repository
        );
        database
            .store()
            .complete_github_check_projection(CompleteGithubCheckProjection::new(
                publish.claim(),
                publish.desired(),
                publish.claimed_at(),
            )?)
            .await?;

        // Admission and its Check link commit before the fire conclusion. A
        // registry refresh in this crash window must fail atomically so the
        // old runtime remains available to conclude the admitted fire.
        let successor_claim = claim_discovery(
            database.store(),
            GithubScheduleRegistryId::from_uuid(Uuid::from_u128(0x5906))?,
            manifest.clone(),
            source_authority.clone(),
            discovery_worker,
        )
        .await?;
        let successor_registry = registry(
            successor_claim,
            manifest.clone(),
            source_authority.clone(),
            "2222222222222222222222222222222222222222",
            [23; 32],
        )?;
        assert!(matches!(
            database
                .store()
                .register_github_schedule_registry(successor_registry.clone())
                .await,
            Err(GithubScheduleStoreError::Conflict)
        ));
        let crash_window_state: (Uuid, String, Option<Uuid>, String) = sqlx::query_as(
            r"
            SELECT current.registry_id, fire.state, subject.workflow_run_id,
                   subject.desired_state
              FROM github_schedule_registry_current AS current
              JOIN github_schedule_fires AS fire
                ON fire.registry_id = current.registry_id
               AND fire.fire_id = $1
              JOIN github_check_subjects AS subject
                ON subject.schedule_fire_id = fire.fire_id
               AND subject.subject_kind = 'workflow'
             WHERE current.provider_connection_id = $2
            ",
        )
        .bind(second.claim().fire_id().as_uuid())
        .bind(connection.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(crash_window_state.0, created.registry_id().as_uuid());
        assert_eq!(crash_window_state.1, "claimed");
        assert_eq!(crash_window_state.2, Some(admitted.run_id().as_uuid()));
        assert_eq!(crash_window_state.3, "in_progress");

        let origin_mutation = sqlx::query(
            r"
            UPDATE github_check_subjects
               SET origin_kind = 'provider_delivery',
                   provider_delivery_id = $2,
                   schedule_fire_id = NULL
             WHERE id = $1
            ",
        )
        .bind(check.subject_id().as_uuid())
        .bind(Uuid::from_u128(0x5908))
        .execute(database.pool())
        .await
        .expect_err("a scheduled Check origin cannot be rewritten");
        assert_eq!(
            origin_mutation
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_check_subjects_origin_immutable")
        );
        let next = UnixMillis::new(database_now(database.pool()).await?.get() + 600_000);
        database
            .store()
            .complete_github_schedule_fire(CompleteGithubScheduleFire::new(
                second.claim(),
                GithubScheduleFireConclusion::Admitted(admitted.run_id()),
                next,
            )?)
            .await?;
        assert!(matches!(
            database
                .store()
                .complete_github_schedule_fire(CompleteGithubScheduleFire::new(
                    second.claim(),
                    GithubScheduleFireConclusion::Admitted(admitted.run_id()),
                    next,
                )?)
                .await,
            Err(GithubScheduleStoreError::ClaimRejected)
        ));
        let audit: Vec<(i16, String)> = sqlx::query_as(
            "SELECT attempt, outcome FROM github_schedule_fire_attempts ORDER BY attempt",
        )
        .fetch_all(database.pool())
        .await?;
        assert_eq!(audit, vec![(1, "retry".into()), (2, "admitted".into())]);

        make_due(database.pool(), created.registry_id()).await?;
        let superseded_claim = database
            .store()
            .claim_due_github_schedule_fire(claim_request)
            .await?
            .expect("second due occurrence");
        let superseded_check = database
            .store()
            .register_github_scheduled_check_subject(RegisterGithubScheduledCheckSubject::new(
                superseded_claim.claim(),
            ))
            .await?;
        database
            .store()
            .register_github_schedule_registry(successor_registry)
            .await?;
        let terminal: (String, Option<String>) = sqlx::query_as(
            "SELECT state, failure_kind FROM github_schedule_fires WHERE fire_id = $1",
        )
        .bind(superseded_claim.claim().fire_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(terminal, ("failed".into(), Some("registry_superseded".into())));
        let terminal_check: (String, Option<String>, Option<String>) = sqlx::query_as(
            r"
            SELECT desired_state, desired_conclusion, terminal_cause
              FROM github_check_subjects
             WHERE id = $1
            ",
        )
        .bind(superseded_check.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            terminal_check,
            (
                "completed".into(),
                Some("failure".into()),
                Some("system_unknown".into())
            )
        );
        let admitted_run_check: (Option<Uuid>, String, Option<String>, i64) = sqlx::query_as(
            r"
            SELECT workflow_run_id, desired_state, desired_conclusion,
                   desired_revision
              FROM github_check_subjects
             WHERE id = $1
               AND subject_kind = 'workflow'
            ",
        )
        .bind(check.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            admitted_run_check,
            (
                Some(admitted.run_id().as_uuid()),
                "in_progress".into(),
                None,
                2,
            ),
            "registry supersession must not terminalize the admitted run Check"
        );
        let active_logical_jobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM logical_workflow_jobs WHERE run_id = $1 AND state = 'pending'",
        )
        .bind(admitted.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            active_logical_jobs, 1,
            "the admitted job must remain active across schedule-registry supersession"
        );
        assert!(matches!(
            database
                .store()
                .renew_github_schedule_fire(superseded_claim.claim(), 60_000)
                .await,
            Err(GithubScheduleStoreError::ClaimRejected)
        ));

        let mutation = sqlx::query(
            "UPDATE github_schedule_registry_entries SET timezone = timezone WHERE registry_id = $1",
        )
        .bind(created.registry_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("sealed entry is immutable");
        assert_eq!(
            mutation
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_schedule_immutable_evidence")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn twentieth_attempt_retry_and_expiry_terminalize_without_sticking_runtime() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap_schedule_fixture(&database).await?;
        let worker = GithubScheduleWorkerId::from_uuid(Uuid::from_u128(0x59a1))?;

        let live = seed_and_claim_twentieth_attempt(
            database.pool(),
            fixture.registry_id,
            worker,
            60_000,
            Uuid::from_u128(0x59a2),
        )
        .await?;
        let live_check = database
            .store()
            .register_github_scheduled_check_subject(RegisterGithubScheduledCheckSubject::new(
                live.claim(),
            ))
            .await?;
        database
            .store()
            .retry_github_schedule_fire(RetryGithubScheduleFire::new(
                live.claim(),
                1_000,
                "provider_transient",
            )?)
            .await?;
        assert_exhausted_fire(database.pool(), &live, live_check.subject_id().as_uuid()).await?;

        let expired = seed_and_claim_twentieth_attempt(
            database.pool(),
            fixture.registry_id,
            worker,
            100,
            Uuid::from_u128(0x59a3),
        )
        .await?;
        let expired_check = database
            .store()
            .register_github_scheduled_check_subject(RegisterGithubScheduledCheckSubject::new(
                expired.claim(),
            ))
            .await?;
        wait_until_database_at_or_after(database.pool(), expired.claim().expires_at().get())
            .await?;
        assert!(
            database
                .store()
                .claim_due_github_schedule_fire(ClaimDueGithubScheduleFire::new(worker, 60_000)?)
                .await?
                .is_none(),
            "expired final attempt is terminalized and its next calendar occurrence is not due"
        );
        assert_exhausted_fire(
            database.pool(),
            &expired,
            expired_check.subject_id().as_uuid(),
        )
        .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn owner_binding_requires_an_explicit_revised_successor() -> TestResult {
    run_with_database(|database| async move {
        let tenant = TenantScope::from_authenticated_tenant_id("schedule-owner-upgrade-test")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(0x59c1))?;
        let legacy = fixture_private_github_manifest_revision(
            tenant.clone(),
            connection,
            202,
            "example/owner-upgrade",
            None,
            1,
            1,
        );
        database
            .store()
            .bootstrap_github_provider_repository(fixture_github_repository_bootstrap(
                legacy.clone(),
                UnixMillis::new(1),
            ))
            .await?;

        let owner_id = ProviderRepositoryOwnerId::new(303)?;
        let unrevisioned = legacy.clone().with_repository_owner_id(owner_id);
        assert!(matches!(
            database
                .store()
                .bootstrap_github_provider_repository(fixture_github_repository_bootstrap(
                    unrevisioned,
                    UnixMillis::new(2),
                ))
                .await,
            Err(GithubProviderManifestStoreError::OwnerBindingRevisionRequired)
        ));

        let successor = fixture_private_github_manifest_revision(
            tenant.clone(),
            connection,
            202,
            "example/owner-upgrade",
            Some(owner_id),
            2,
            2,
        );
        let upgraded = database
            .store()
            .bootstrap_github_provider_repository(fixture_github_repository_bootstrap(
                successor.clone(),
                UnixMillis::new(3),
            ))
            .await?;
        assert!(!upgraded.manifest().is_replay());
        assert_eq!(upgraded.manifest().current().manifest(), &successor);

        let historical = database
            .store()
            .load_github_provider_manifest_revision(
                &tenant,
                connection,
                GithubProviderManifestRevision::new(1)?,
            )
            .await?;
        assert_eq!(historical.manifest(), &legacy);
        assert_eq!(historical.manifest().github_repository_owner_id(), None);
        assert_ne!(historical.manifest().digest(), successor.digest());
        Ok(())
    })
    .await
}

struct ScheduleFixture {
    registry_id: GithubScheduleRegistryId,
}

async fn bootstrap_schedule_fixture(
    database: &crate::support::TestDatabase,
) -> TestResult<ScheduleFixture> {
    let tenant = TenantScope::from_authenticated_tenant_id("schedule-exhaustion-test")?;
    let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(0x59b1))?;
    let manifest = fixture_private_github_manifest(tenant, connection);
    database
        .store()
        .bootstrap_github_provider_repository(fixture_github_repository_bootstrap(
            manifest.clone(),
            UnixMillis::new(1),
        ))
        .await?;
    let configured_at = database_now(database.pool()).await?;
    for (authority_id, scope, fingerprint) in [
        (
            Uuid::from_u128(0x59b2),
            GithubServerServiceScope::ChecksWrite,
            [71; 32],
        ),
        (
            Uuid::from_u128(0x59b3),
            GithubServerServiceScope::PrivateRepositorySourceRead,
            [72; 32],
        ),
    ] {
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                schedule_authority_identity(&manifest, authority_id, scope, fingerprint)?,
                configured_at,
            )?)
            .await?;
    }
    let private_identity = schedule_authority_identity(
        &manifest,
        Uuid::from_u128(0x59b3),
        GithubServerServiceScope::PrivateRepositorySourceRead,
        [72; 32],
    )?;
    let source_authority = GithubScheduleSourceAuthority::Private(
        GithubServerServiceAuthoritySelector::from_identity(&private_identity),
    );
    let registry_id = GithubScheduleRegistryId::from_uuid(Uuid::from_u128(0x59b4))?;
    let claim = claim_discovery(
        database.store(),
        registry_id,
        manifest.clone(),
        source_authority.clone(),
        GithubScheduleWorkerId::from_uuid(Uuid::from_u128(0x59b5))?,
    )
    .await?;
    database
        .store()
        .register_github_schedule_registry(registry(
            claim,
            manifest,
            source_authority,
            SOURCE_REVISION,
            [73; 32],
        )?)
        .await?;
    Ok(ScheduleFixture { registry_id })
}

const SOURCE_REVISION: &str = "1111111111111111111111111111111111111111";

fn schedule_authority_identity(
    manifest: &GithubProviderManifest,
    authority_id: Uuid,
    scope: GithubServerServiceScope,
    fingerprint: [u8; 32],
) -> Result<GithubServerServiceAuthorityIdentity, Box<dyn std::error::Error + Send + Sync>> {
    Ok(GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(authority_id)?,
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
        Sha256Digest::from_bytes(fingerprint),
    )?)
}

fn registry(
    discovery_claim: GithubScheduleDiscoveryClaim,
    manifest: automata_ci_store::GithubProviderManifest,
    source_authority: GithubScheduleSourceAuthority,
    source_revision: &str,
    archive_digest: [u8; 32],
) -> Result<RegisterGithubScheduleRegistry, Box<dyn std::error::Error + Send + Sync>> {
    let digest = Sha256Digest::from_bytes(archive_digest);
    let archive = GithubScheduleArchive::new(
        digest,
        ObjectKey::new(format!("github/schedule-archives/sha256/{digest}.tar.gz"))?,
        128,
    )?;
    let cron_expression = "0/5 * * * *";
    let timezone = "UTC";
    let next_fire_at = CronExpression::parse(cron_expression)?
        .next_after(discovery_claim.claimed_at(), timezone)?;
    let entry = GithubScheduleRegistryEntry::new(
        0,
        GithubCheckSubjectKey::new(".ci/workflows/neutral.yml")?,
        Sha256Digest::from_bytes([41; 32]),
        0,
        cron_expression,
        timezone,
        next_fire_at,
    )?;
    Ok(RegisterGithubScheduleRegistry::new(
        discovery_claim,
        manifest,
        source_authority,
        source_revision,
        archive,
        vec![entry],
    )?)
}

async fn claim_discovery(
    store: &PostgresStore,
    registry_id: GithubScheduleRegistryId,
    manifest: GithubProviderManifest,
    source_authority: GithubScheduleSourceAuthority,
    worker: GithubScheduleWorkerId,
) -> Result<GithubScheduleDiscoveryClaim, Box<dyn std::error::Error + Send + Sync>> {
    Ok(store
        .claim_github_schedule_discovery(ClaimGithubScheduleDiscovery::new(
            registry_id,
            manifest,
            ProviderRepositoryOwnerId::new(303)?,
            source_authority,
            worker,
            300_000,
        )?)
        .await?)
}

fn fixture_private_github_manifest(
    tenant: TenantScope,
    connection: ProviderConnectionId,
) -> GithubProviderManifest {
    fixture_private_github_manifest_for_repository(
        tenant,
        connection,
        202,
        "example/neutral-schedules",
    )
}

fn fixture_private_github_manifest_for_repository(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    github_repository_id: u64,
    github_repository_name: &str,
) -> GithubProviderManifest {
    fixture_private_github_manifest_revision(
        tenant,
        connection,
        github_repository_id,
        github_repository_name,
        Some(ProviderRepositoryOwnerId::new(303).expect("fixture owner")),
        1,
        1,
    )
}

#[allow(clippy::too_many_arguments)]
fn fixture_private_github_manifest_revision(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    github_repository_id: u64,
    github_repository_name: &str,
    repository_owner_id: Option<ProviderRepositoryOwnerId>,
    manifest_revision: u64,
    policy_revision: u64,
) -> GithubProviderManifest {
    let runtime = fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        tenant,
        connection,
        ProviderInstallationId::new(101).expect("fixture installation"),
        ProviderRepositoryId::new(github_repository_id).expect("fixture repository"),
        GithubRepositoryName::new(github_repository_name).expect("fixture repository name"),
        ProviderRepositoryVisibility::Private,
        GithubServerServiceAppId::new(303).expect("fixture App"),
        GithubServerServiceAppClientId::new("Iv1.1111111111111111").expect("fixture client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([7; 32]),
        GithubServerServiceRevision::new(1).expect("fixture App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([9; 32]))
            .expect("fixture verifier"),
        GithubServerServiceRevision::new(1).expect("fixture verifier revision"),
        GithubServerServiceRevision::new(policy_revision).expect("fixture policy revision"),
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime.runner_policy,
        runtime.revision,
        runtime.semantic_digest,
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
        GithubCheckName::new("Neutral CI").expect("fixture Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(manifest_revision).expect("fixture manifest revision"),
    );
    if let Some(repository_owner_id) = repository_owner_id {
        manifest.with_repository_owner_id(repository_owner_id)
    } else {
        manifest
    }
}

fn scheduled_command(
    manifest: &automata_ci_store::GithubProviderManifest,
    fire: &ClaimedGithubScheduleFire,
    admitted_at: UnixMillis,
) -> TestResult<AdmitLogicalWorkflowRun> {
    let run_id = RunId::from_uuid(Uuid::from_u128(0x5910));
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(0x5911));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(0x5912));
    let root_invocation_id = LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(0x5913))?;
    let job = AdmittedLogicalWorkflowJob::new(
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(0x5914))?,
        WorkflowJobKey::new("verify")?,
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )?;
    Ok(AdmitLogicalWorkflowRun::builder(
        manifest.tenant().clone(),
        WorkflowAdmissionIdempotency::operation(OperationId::from_uuid(
            fire.claim().fire_id().as_uuid(),
        )),
        Sha256Digest::from_bytes([61; 32]),
        AdmissionRepository::new(
            manifest.repository_id(),
            "github",
            manifest.github_repository_id().get().to_string(),
            fire.repository_owner(),
            fire.repository_name(),
        )?,
        workflow_id,
        fire.entry().workflow_path(),
        "Neutral scheduled verification",
        fire.default_branch_ref(),
        snapshot_id,
        admission_object(
            "github/schedule-workflows/neutral.yml",
            41,
            "application/vnd.automata.github-workflow+yaml",
        )?,
        admission_object(
            "github/schedule-plans/neutral.json",
            62,
            "application/vnd.automata.workflow-plan+json",
        )?,
        run_id,
        1,
        root_invocation_id,
        "schedule",
        admission_object(
            "github/schedule-events/neutral.json",
            63,
            "application/json",
        )?,
        vec![0x11; 20],
        vec![job],
        admitted_at,
    )
    .base_context(admission_object(
        "github/schedule-context/neutral.pb",
        64,
        "application/vnd.automata.job-runtime-context.protobuf",
    )?)
    .actor(GITHUB_SCHEDULE_SERVICE_ACTOR)
    .build()?)
}

fn admission_object(key: &str, byte: u8, media_type: &str) -> TestResult<AdmissionObject> {
    Ok(AdmissionObject::new(
        Sha256Digest::from_bytes([byte; 32]),
        ObjectKey::new(key)?,
        128,
        media_type,
    )?)
}

async fn make_due(pool: &sqlx::PgPool, registry_id: GithubScheduleRegistryId) -> TestResult {
    sqlx::query(
        r"
        UPDATE github_schedule_runtime
           SET next_fire_at_ms = floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT - 1
         WHERE registry_id = $1
        ",
    )
    .bind(registry_id.as_uuid())
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_and_claim_twentieth_attempt(
    pool: &sqlx::PgPool,
    registry_id: GithubScheduleRegistryId,
    worker: GithubScheduleWorkerId,
    lease_millis: i64,
    fire_id: Uuid,
) -> TestResult<ClaimedGithubScheduleFire> {
    make_due(pool, registry_id).await?;
    let (tenant, repository_id, connection_id, entry_ordinal, scheduled_at): (
        String,
        Uuid,
        Uuid,
        i16,
        i64,
    ) = sqlx::query_as(
        r"
        SELECT tenant_id, repository_id, provider_connection_id,
               entry_ordinal, next_fire_at_ms
          FROM github_schedule_runtime
         WHERE registry_id = $1
        ",
    )
    .bind(registry_id.as_uuid())
    .fetch_one(pool)
    .await?;
    let now = database_now(pool).await?.get();
    sqlx::query(
        r"
        INSERT INTO github_schedule_fires (
            fire_id, tenant_id, repository_id, provider_connection_id,
            registry_id, entry_ordinal, scheduled_at_ms, state,
            attempt_count, claim_fence, next_attempt_at_ms,
            created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', 19, 19, $7, $8, $8)
        ",
    )
    .bind(fire_id)
    .bind(tenant)
    .bind(repository_id)
    .bind(connection_id)
    .bind(registry_id.as_uuid())
    .bind(entry_ordinal)
    .bind(scheduled_at)
    .bind(now)
    .execute(pool)
    .await?;
    let claimed = PostgresStore::from_postgres_pool(pool.clone())
        .claim_due_github_schedule_fire(ClaimDueGithubScheduleFire::new(worker, lease_millis)?)
        .await?
        .expect("seeded nineteenth-attempt fire is due");
    assert_eq!(claimed.claim().fire_id().as_uuid(), fire_id);
    assert_eq!(claimed.claim().attempt(), MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS);
    Ok(claimed)
}

async fn assert_exhausted_fire(
    pool: &sqlx::PgPool,
    fire: &ClaimedGithubScheduleFire,
    check_subject_id: Uuid,
) -> TestResult {
    let terminal: (String, i16, Option<String>) = sqlx::query_as(
        "SELECT state, attempt_count, failure_kind FROM github_schedule_fires WHERE fire_id = $1",
    )
    .bind(fire.claim().fire_id().as_uuid())
    .fetch_one(pool)
    .await?;
    assert_eq!(
        terminal,
        (
            "failed".into(),
            i16::try_from(MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS).expect("attempt bound"),
            Some(GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE.into())
        )
    );
    let attempt: (String, Option<String>) = sqlx::query_as(
        "SELECT outcome, failure_kind FROM github_schedule_fire_attempts WHERE fire_id = $1 AND attempt = $2",
    )
    .bind(fire.claim().fire_id().as_uuid())
    .bind(i16::try_from(MAX_GITHUB_SCHEDULE_FIRE_ATTEMPTS).expect("attempt bound"))
    .fetch_one(pool)
    .await?;
    assert_eq!(
        attempt,
        (
            "failed".into(),
            Some(GITHUB_SCHEDULE_ATTEMPTS_EXHAUSTED_FAILURE.into())
        )
    );
    let next_fire_at: i64 = sqlx::query_scalar(
        "SELECT next_fire_at_ms FROM github_schedule_runtime WHERE registry_id = $1 AND entry_ordinal = $2",
    )
    .bind(fire.registry_id().as_uuid())
    .bind(i16::try_from(fire.entry().ordinal()).expect("entry ordinal"))
    .fetch_one(pool)
    .await?;
    assert!(next_fire_at > fire.scheduled_at().get());
    let check: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT desired_state, desired_conclusion, terminal_cause FROM github_check_subjects WHERE id = $1",
    )
    .bind(check_subject_id)
    .fetch_one(pool)
    .await?;
    assert_eq!(
        check,
        (
            "completed".into(),
            Some("failure".into()),
            Some("system_unknown".into())
        )
    );
    Ok(())
}

async fn database_now(pool: &sqlx::PgPool) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(pool)
            .await?,
    ))
}

async fn assert_schedule_repository_scoping(pool: &sqlx::PgPool) -> TestResult {
    let runtime_primary_key: String = sqlx::query_scalar(
        r"
        SELECT pg_get_constraintdef(oid)
          FROM pg_constraint
         WHERE conrelid = 'github_schedule_runtime'::regclass
           AND conname = 'github_schedule_runtime_primary_key'
        ",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(
        runtime_primary_key,
        "PRIMARY KEY (tenant_id, repository_id, provider_connection_id, entry_ordinal)"
    );
    let replay_identity: String = sqlx::query_scalar(
        r"
        SELECT pg_get_constraintdef(oid)
          FROM pg_constraint
         WHERE conrelid = 'github_schedule_registry_revisions'::regclass
           AND conname = 'github_schedule_registry_revisions_replay_unique'
        ",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(
        replay_identity,
        "UNIQUE (tenant_id, repository_id, provider_connection_id, manifest_revision, source_revision, inventory_digest)"
    );
    Ok(())
}

async fn wait_until_database_at_or_after(pool: &sqlx::PgPool, target: i64) -> TestResult {
    for _ in 0..100 {
        if database_now(pool).await?.get() >= target {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Err("database clock did not reach the expected retry instant".into())
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some(expected)
    );
}
