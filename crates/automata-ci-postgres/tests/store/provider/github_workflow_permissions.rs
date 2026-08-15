use crate::{
    github_manifest_fixture,
    support::{TestDatabase, TestResult, run_with_database},
};

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_key_management::{EncryptedEnvelope, KeyId, WrappedDataKey};
use automata_ci_store::{
    AcquireGithubServerServiceHandoff, BeginGithubServerServiceMint,
    BootstrapGithubProviderRepository, ClaimGithubServerServiceRevocation,
    ClaimNextGithubServerServiceMaintenance, EnsureGithubServerServiceAuthority,
    FinalizeGithubWorkflowPermissionObservation, FinishGithubServerServiceMint,
    FinishGithubServerServiceRevocation, GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS,
    GithubCheckName, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceAuthoritySelector,
    GithubServerServiceAuthorityState, GithubServerServiceEnvelopeMetadata,
    GithubServerServiceGeneration, GithubServerServiceHandoffId, GithubServerServiceIssuanceKey,
    GithubServerServiceJwtIssuer, GithubServerServiceMaintenanceOutcome,
    GithubServerServiceRevision, GithubServerServiceScope, GithubServerServiceWorkerId,
    GithubWorkflowPermissionDefaultsObservation, GithubWorkflowPermissionDefaultsObservationError,
    GithubWorkflowPermissionDefaultsObservationRepository as _,
    GithubWorkflowPermissionHandoffReconciliation, GithubWorkflowPermissionObservationCandidate,
    ProtectedGithubServerServiceCredential, ProviderConnectionId, ProviderInstallationId,
    ProviderRepositoryId, ProviderRepositoryVisibility, ReconcileGithubWorkflowPermissionHandoff,
    ReleaseGithubServerServiceHandoff, RetireGithubServerServiceAuthority, TenantScope,
};
use sqlx::{AssertSqlSafe, PgConnection, PgPool, Postgres, Transaction};
use tokio::time::{Duration, timeout};
use uuid::Uuid;

const INSTALLATION_ID: u64 = 101;
const GITHUB_REPOSITORY_ID: u64 = 202;
const APP_ID: u64 = 303;
const BASE_TIME: i64 = 2_700_000_000_000;

#[derive(Clone)]
struct RevisionFixture {
    manifest: GithubProviderManifest,
    bootstrap: BootstrapGithubProviderRepository,
    authority: GithubServerServiceAuthorityIdentity,
}

struct ObservationAttempt {
    candidate: GithubWorkflowPermissionObservationCandidate,
    handoff_id: GithubServerServiceHandoffId,
    generation: GithubServerServiceGeneration,
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_candidate_graph_is_installed_and_candidate_replay_is_exact() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, BASE_TIME).await?;
        assert_workflow_permission_migration_catalog(&database).await?;
        let tenant = tenant("workflow-permission-candidate")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let fixture = prepare_revision(&database, tenant, connection, 1, BASE_TIME).await?;
        let candidate = candidate(&fixture, BASE_TIME + 1_000)?;

        set_database_test_clock(&database, candidate.claimed_at().get()).await?;
        database
            .store()
            .claim_github_workflow_permission_observation(candidate.clone())
            .await?;
        database
            .store()
            .claim_github_workflow_permission_observation(candidate.clone())
            .await?;

        let sql_digest: Vec<u8> = sqlx::query_scalar(
            "SELECT automata_github_workflow_permission_candidate_digest(candidate) \
             FROM github_workflow_permission_observation_candidates AS candidate \
             WHERE observation_id = $1",
        )
        .bind(candidate.observation_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(sql_digest, candidate.digest().as_bytes());

        let collision = GithubWorkflowPermissionObservationCandidate::new(
            &fixture.bootstrap,
            &fixture.authority,
            candidate.observation_id(),
            GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
            candidate.claimed_at(),
        )?;
        assert_ne!(collision.digest(), candidate.digest());
        assert_eq!(
            database
                .store()
                .claim_github_workflow_permission_observation(collision)
                .await,
            Err(GithubWorkflowPermissionDefaultsObservationError::Conflict)
        );

        let null_digest = clone_candidate_with_digest(
            &database,
            candidate.observation_id().as_uuid(),
            Uuid::new_v4(),
            None,
        )
        .await
        .expect_err("a NULL candidate digest must fail closed");
        assert_eq!(
            null_digest
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23502")
        );

        let tampered = clone_candidate_with_digest(
            &database,
            candidate.observation_id().as_uuid(),
            Uuid::new_v4(),
            Some(candidate.digest().as_bytes().as_slice()),
        )
        .await
        .expect_err("a digest copied onto another observation identity must fail closed");
        assert_constraint(&tampered, "github_workflow_permission_candidate_exact");

        let immutable = sqlx::query(
            "UPDATE github_workflow_permission_observation_candidates \
             SET expected_default = 'write' WHERE observation_id = $1",
        )
        .bind(candidate.observation_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("candidate evidence must be immutable");
        assert_eq!(
            immutable
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23000")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn matching_mismatching_and_stale_observations_drive_a_monotonic_head() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, BASE_TIME).await?;
        let tenant = tenant("workflow-permission-head")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let fixture = prepare_revision(&database, tenant, connection, 1, BASE_TIME).await?;

        let older = begin_observation(&database, &fixture, BASE_TIME + 1_000).await?;
        let newer = begin_observation(&database, &fixture, BASE_TIME + 11_000).await?;
        let newer_id = newer.candidate.observation_id().as_uuid();
        let newer_request = finalization(
            &fixture,
            newer,
            BASE_TIME + 11_100,
            BASE_TIME + 11_200,
            false,
        )?;
        set_database_test_clock(&database, BASE_TIME + 11_200).await?;
        assert!(
            database
                .store()
                .finalize_github_workflow_permission_observation(newer_request)
                .await?
        );

        let stale_request =
            finalization(&fixture, older, BASE_TIME + 1_100, BASE_TIME + 1_200, false)?;
        set_database_test_clock(&database, BASE_TIME + 11_300).await?;
        assert!(
            database
                .store()
                .finalize_github_workflow_permission_observation(stale_request)
                .await?,
            "an older matching observation must retain the newer Ready head"
        );
        assert_head(&database, &fixture, newer_id, "ready", BASE_TIME + 11_100).await?;

        let mismatch = begin_observation(&database, &fixture, BASE_TIME + 21_000).await?;
        let mismatch_id = mismatch.candidate.observation_id().as_uuid();
        let mismatch_request = finalization(
            &fixture,
            mismatch,
            BASE_TIME + 21_100,
            BASE_TIME + 21_200,
            true,
        )?;
        set_database_test_clock(&database, BASE_TIME + 21_200).await?;
        assert!(
            !database
                .store()
                .finalize_github_workflow_permission_observation(mismatch_request)
                .await?
        );
        assert_head(
            &database,
            &fixture,
            mismatch_id,
            "invalid",
            BASE_TIME + 21_100,
        )
        .await?;

        let recovery = begin_observation(&database, &fixture, BASE_TIME + 31_000).await?;
        let recovery_id = recovery.candidate.observation_id().as_uuid();
        let recovery_request = finalization(
            &fixture,
            recovery,
            BASE_TIME + 31_100,
            BASE_TIME + 31_200,
            false,
        )?;
        set_database_test_clock(&database, BASE_TIME + 31_200).await?;
        assert!(
            database
                .store()
                .finalize_github_workflow_permission_observation(recovery_request.clone())
                .await?
        );
        assert!(
            database
                .store()
                .finalize_github_workflow_permission_observation(recovery_request)
                .await?
        );
        assert_head(
            &database,
            &fixture,
            recovery_id,
            "ready",
            BASE_TIME + 31_100,
        )
        .await?;

        let graph: (i64, i64, i64) = sqlx::query_as(
            "SELECT \
                (SELECT count(*) FROM github_workflow_permission_observation_candidates), \
                (SELECT count(*) FROM github_workflow_permission_default_observations), \
                (SELECT count(*) FROM github_server_service_authority_handoffs \
                 WHERE consumer_action = 'observe_workflow_permission_defaults' \
                   AND released_at_ms IS NOT NULL)",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(graph, (4, 4, 4));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn exact_finalization_replay_after_revision_advance_is_a_false_noop() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, BASE_TIME).await?;
        let tenant = tenant("workflow-permission-replay-after-advance")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let revision_1 =
            prepare_revision(&database, tenant.clone(), connection, 1, BASE_TIME).await?;
        let attempt_1 = begin_observation(&database, &revision_1, BASE_TIME + 1_000).await?;
        let request_1 = finalization(
            &revision_1,
            attempt_1,
            BASE_TIME + 1_100,
            BASE_TIME + 1_200,
            false,
        )?;
        set_database_test_clock(&database, BASE_TIME + 1_200).await?;
        assert!(
            database
                .store()
                .finalize_github_workflow_permission_observation(request_1.clone())
                .await?
        );

        let revision_2 =
            prepare_revision(&database, tenant, connection, 2, BASE_TIME + 10_000).await?;
        let attempt_2 = begin_observation(&database, &revision_2, BASE_TIME + 11_000).await?;
        let revision_2_id = attempt_2.candidate.observation_id().as_uuid();
        let request_2 = finalization(
            &revision_2,
            attempt_2,
            BASE_TIME + 11_100,
            BASE_TIME + 11_200,
            false,
        )?;
        set_database_test_clock(&database, BASE_TIME + 11_200).await?;
        assert!(
            database
                .store()
                .finalize_github_workflow_permission_observation(request_2)
                .await?
        );

        set_database_test_clock(&database, BASE_TIME + 11_300).await?;
        assert!(
            !database
                .store()
                .finalize_github_workflow_permission_observation(request_1)
                .await?,
            "an exact historical replay must commit as a false no-op"
        );
        assert_head(
            &database,
            &revision_2,
            revision_2_id,
            "ready",
            BASE_TIME + 11_100,
        )
        .await?;
        let graph: (i64, i64, i64) = sqlx::query_as(
            "SELECT \
                (SELECT count(*) FROM github_workflow_permission_observation_candidates), \
                (SELECT count(*) FROM github_workflow_permission_default_observations), \
                (SELECT count(*) FROM github_server_service_authority_handoffs \
                 WHERE consumer_action = 'observe_workflow_permission_defaults')",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(graph, (2, 2, 2));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn historical_policy_admission_requires_a_strictly_fresh_current_head() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, BASE_TIME).await?;
        let tenant = tenant("workflow-permission-historical-policy")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let revision_1 =
            prepare_revision(&database, tenant.clone(), connection, 1, BASE_TIME).await?;
        finalize_matching(&database, &revision_1, BASE_TIME + 1_000, BASE_TIME + 1_100).await?;

        let revision_2 =
            prepare_revision(&database, tenant, connection, 2, BASE_TIME + 10_000).await?;
        let current_observed_at = BASE_TIME + 11_100;
        finalize_matching(
            &database,
            &revision_2,
            BASE_TIME + 11_000,
            current_observed_at,
        )
        .await?;

        let historical_policy: (i64, Vec<u8>) = sqlx::query_as(
            "SELECT policy_revision, policy_digest \
             FROM workflow_runtime_policy_revisions \
             WHERE tenant_id = $1 AND repository_id = $2 AND policy_revision = 1",
        )
        .bind(revision_1.manifest.tenant().as_str())
        .bind(revision_1.manifest.repository_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let current: (i64, i64) = sqlx::query_as(
            "SELECT policy.policy_revision, head.fresh_through_ms \
             FROM workflow_runtime_policy_current AS policy \
             JOIN github_workflow_permission_default_heads AS head \
               ON head.tenant_id = policy.tenant_id \
              AND head.repository_id = policy.repository_id \
              AND head.runtime_policy_revision = policy.policy_revision \
              AND head.runtime_policy_digest = policy.policy_digest \
             WHERE policy.tenant_id = $1 AND policy.repository_id = $2",
        )
        .bind(revision_1.manifest.tenant().as_str())
        .bind(revision_1.manifest.repository_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(current.0, 2);
        assert_eq!(
            current.1,
            current_observed_at + GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS
        );

        set_database_test_clock(&database, current.1 - 1).await?;
        let mut fresh = database.pool().begin().await?;
        disable_pin_provenance(&mut fresh).await?;
        insert_policy_pin(
            &mut fresh,
            &revision_1,
            historical_policy.0,
            &historical_policy.1,
            current.1 - 1,
        )
        .await?;
        fresh.rollback().await?;

        set_database_test_clock(&database, current.1).await?;
        let mut expired = database.pool().begin().await?;
        disable_pin_provenance(&mut expired).await?;
        let error = insert_policy_pin(
            &mut expired,
            &revision_1,
            historical_policy.0,
            &historical_policy.1,
            current.1,
        )
        .await
        .expect_err("the exclusive freshness horizon must fail at exact expiry");
        assert_constraint(&error, "logical_workflow_permission_defaults_fresh");
        expired.rollback().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn admission_waiting_on_head_lock_rechecks_the_exact_freshness_boundary() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, BASE_TIME).await?;
        let tenant = tenant("workflow-permission-lock-expiry")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let fixture = prepare_revision(&database, tenant, connection, 1, BASE_TIME).await?;
        let provider_observed_at = BASE_TIME + 1_100;
        finalize_matching(&database, &fixture, BASE_TIME + 1_000, provider_observed_at).await?;
        let fresh_through =
            provider_observed_at + GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS;
        let policy: (i64, Vec<u8>) = sqlx::query_as(
            "SELECT policy_revision, policy_digest \
             FROM workflow_runtime_policy_current \
             WHERE tenant_id = $1 AND repository_id = $2",
        )
        .bind(fixture.manifest.tenant().as_str())
        .bind(fixture.manifest.repository_id().as_uuid())
        .fetch_one(database.pool())
        .await?;

        let mut admission = database.pool().begin().await?;
        disable_pin_provenance(&mut admission).await?;
        let admission_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *admission)
            .await?;
        let mut head_lock = database.pool().begin().await?;
        sqlx::query(
            "SELECT observation_id FROM github_workflow_permission_default_heads \
             WHERE tenant_id = $1 AND repository_id = $2 \
               AND provider_connection_id = $3 FOR UPDATE",
        )
        .bind(fixture.manifest.tenant().as_str())
        .bind(fixture.manifest.repository_id().as_uuid())
        .bind(fixture.manifest.connection_id().as_uuid())
        .fetch_one(&mut *head_lock)
        .await?;

        set_database_test_clock(&database, fresh_through - 1).await?;
        let admission_fixture = fixture.clone();
        let admission_task = tokio::spawn(async move {
            let result = insert_policy_pin(
                &mut admission,
                &admission_fixture,
                policy.0,
                &policy.1,
                fresh_through - 1,
            )
            .await;
            let rollback = admission.rollback().await;
            (result, rollback)
        });
        wait_for_backend_lock(database.pool(), admission_pid).await?;
        set_database_test_clock(&database, fresh_through).await?;
        head_lock.rollback().await?;

        let (result, rollback) = admission_task.await?;
        let error = result.expect_err("a lock wait across exact expiry must fail closed");
        assert_constraint(&error, "logical_workflow_permission_defaults_fresh");
        rollback?;
        let pin_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM logical_workflow_runtime_policy_pins \
             WHERE tenant_id = $1 AND repository_id = $2",
        )
        .bind(fixture.manifest.tenant().as_str())
        .bind(fixture.manifest.repository_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(pin_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn ambiguous_handoff_reconciliation_survives_authority_retirement() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, BASE_TIME).await?;
        let tenant = tenant("workflow-permission-retirement")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let fixture = prepare_revision(&database, tenant, connection, 1, BASE_TIME).await?;
        let attempt = begin_observation(&database, &fixture, BASE_TIME + 1_000).await?;
        let request = ReconcileGithubWorkflowPermissionHandoff::new(attempt.candidate.clone())?;

        set_database_test_clock(&database, BASE_TIME + 1_010).await?;
        let retiring = database
            .store()
            .retire_github_server_service_authority(RetireGithubServerServiceAuthority::new(
                selector(&fixture.authority),
                UnixMillis::new(BASE_TIME + 1_010),
            )?)
            .await?;
        assert_eq!(
            retiring.state(),
            GithubServerServiceAuthorityState::Retiring
        );

        set_database_test_clock(&database, BASE_TIME + 1_020).await?;
        let reconciled = database
            .store()
            .reconcile_github_workflow_permission_handoff(request.clone())
            .await?;
        assert!(matches!(
            reconciled,
            GithubWorkflowPermissionHandoffReconciliation::Released {
                handoff_id,
                generation,
                released_at,
            } if handoff_id == attempt.handoff_id
                && generation == attempt.generation
                && released_at == UnixMillis::new(BASE_TIME + 1_020)
        ));

        let issuance_key = GithubServerServiceIssuanceKey::new(
            fixture.authority.authority_id(),
            attempt.generation,
        );
        set_database_test_clock(&database, BASE_TIME + 1_030).await?;
        let revocation = database
            .store()
            .claim_github_server_service_revocation(ClaimGithubServerServiceRevocation::new(
                selector(&fixture.authority),
                issuance_key,
                GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                UnixMillis::new(BASE_TIME + 1_030),
                UnixMillis::new(BASE_TIME + 2_030),
            )?)
            .await?;
        set_database_test_clock(&database, BASE_TIME + 1_040).await?;
        database
            .store()
            .finish_github_server_service_revocation(
                FinishGithubServerServiceRevocation::confirmed(
                    revocation.claim().clone(),
                    UnixMillis::new(BASE_TIME + 1_040),
                )?,
            )
            .await?;
        let retired = database
            .store()
            .inspect_github_server_service_authority(
                fixture.authority.tenant(),
                fixture.authority.authority_id(),
            )
            .await?;
        assert_eq!(retired.state(), GithubServerServiceAuthorityState::Retired);

        set_database_test_clock(&database, BASE_TIME + 1_050).await?;
        assert_eq!(
            database
                .store()
                .reconcile_github_workflow_permission_handoff(request)
                .await?,
            reconciled,
            "retirement must not make an exact durable closure unreplayable"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn direct_handoff_insert_waits_for_authority_before_retirement_issuance_lock() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, BASE_TIME).await?;
        let tenant = tenant("workflow-permission-handoff-lock-order")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let fixture = prepare_revision(&database, tenant, connection, 1, BASE_TIME).await?;
        let candidate = candidate(&fixture, BASE_TIME + 1_000)?;
        set_database_test_clock(&database, candidate.claimed_at().get()).await?;
        database
            .store()
            .claim_github_workflow_permission_observation(candidate.clone())
            .await?;

        let mut retirement = database.pool().begin().await?;
        sqlx::query(
            "SELECT id FROM github_server_service_authorities \
             WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(fixture.authority.tenant().as_str())
        .bind(fixture.authority.authority_id().as_uuid())
        .fetch_one(&mut *retirement)
        .await?;

        let mut handoff_connection = database.pool().acquire().await?;
        let waiting_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *handoff_connection)
            .await?;
        let proposed_handoff_id = GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?;
        let handoff_candidate = candidate.clone();
        let handoff_task = tokio::spawn(async move {
            insert_workflow_permission_handoff(
                &mut handoff_connection,
                proposed_handoff_id,
                GithubServerServiceGeneration::new(1).map_err(invalid_sql_binding)?,
                &handoff_candidate,
            )
            .await
        });
        wait_for_backend_lock(database.pool(), waiting_backend_pid).await?;

        sqlx::query("SET LOCAL lock_timeout = '2s'")
            .execute(&mut *retirement)
            .await?;
        sqlx::query(
            "SELECT generation FROM github_server_service_authority_issuances \
             WHERE tenant_id = $1 AND authority_id = $2 AND generation = 1 FOR UPDATE",
        )
        .bind(fixture.authority.tenant().as_str())
        .bind(fixture.authority.authority_id().as_uuid())
        .fetch_one(&mut *retirement)
        .await?;
        let retirement_at = candidate.claimed_at().get() + 1;
        set_database_test_clock(&database, retirement_at).await?;
        let authority_update = sqlx::query(
            "UPDATE github_server_service_authorities \
             SET state = 'retiring', current_issuance_generation = NULL, \
                 refresh_issuance_generation = NULL, state_updated_at_ms = $3 \
             WHERE tenant_id = $1 AND id = $2 AND state = 'active'",
        )
        .bind(fixture.authority.tenant().as_str())
        .bind(fixture.authority.authority_id().as_uuid())
        .bind(retirement_at)
        .execute(&mut *retirement)
        .await?;
        assert_eq!(authority_update.rows_affected(), 1);
        let issuance_update = sqlx::query(
            "UPDATE github_server_service_authority_issuances \
             SET state = 'revoke_pending', state_updated_at_ms = $3 \
             WHERE tenant_id = $1 AND authority_id = $2 \
               AND generation = 1 AND state = 'ready'",
        )
        .bind(fixture.authority.tenant().as_str())
        .bind(fixture.authority.authority_id().as_uuid())
        .bind(retirement_at)
        .execute(&mut *retirement)
        .await?;
        assert_eq!(issuance_update.rows_affected(), 1);
        retirement.commit().await?;

        let error = handoff_task
            .await?
            .expect_err("a handoff waiting behind retirement must fail closed");
        assert_constraint(&error, "github_workflow_permission_handoff_exact");
        let handoff_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_server_service_authority_handoffs WHERE id = $1",
        )
        .bind(proposed_handoff_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(handoff_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn candidate_and_matching_observation_resample_time_after_decision_locks() -> TestResult {
    run_with_database(|database| async move {
        install_database_test_clock(&database, BASE_TIME).await?;
        let tenant = tenant("workflow-permission-evidence-lock-clock")?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let fixture = prepare_revision(&database, tenant, connection, 1, BASE_TIME).await?;

        let blocked_candidate = candidate(&fixture, BASE_TIME + 1_000)?;
        set_database_test_clock(&database, blocked_candidate.claimed_at().get()).await?;
        let mut authority_lock = database.pool().begin().await?;
        sqlx::query(
            "SELECT id FROM github_server_service_authorities \
             WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(fixture.authority.tenant().as_str())
        .bind(fixture.authority.authority_id().as_uuid())
        .fetch_one(&mut *authority_lock)
        .await?;
        let mut candidate_connection = database.pool().acquire().await?;
        let candidate_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *candidate_connection)
            .await?;
        let rejected_candidate_id = blocked_candidate.observation_id().as_uuid();
        let candidate_expires_at = blocked_candidate.expires_at().get();
        let candidate_task = tokio::spawn(async move {
            insert_workflow_permission_candidate(&mut candidate_connection, &blocked_candidate)
                .await
        });
        wait_for_backend_lock(database.pool(), candidate_backend_pid).await?;
        set_database_test_clock(&database, candidate_expires_at).await?;
        authority_lock.rollback().await?;
        let candidate_error = candidate_task
            .await?
            .expect_err("a candidate waiting through expiry must fail closed");
        assert_constraint(
            &candidate_error,
            "github_workflow_permission_candidate_exact",
        );
        let candidate_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_workflow_permission_observation_candidates \
             WHERE observation_id = $1",
        )
        .bind(rejected_candidate_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(candidate_count, 0);

        let initial = begin_observation(&database, &fixture, BASE_TIME + 10_000).await?;
        let initial_request = finalization(
            &fixture,
            initial,
            BASE_TIME + 10_100,
            BASE_TIME + 10_200,
            false,
        )?;
        set_database_test_clock(&database, BASE_TIME + 10_200).await?;
        assert!(
            database
                .store()
                .finalize_github_workflow_permission_observation(initial_request)
                .await?
        );

        let attempt = begin_observation(&database, &fixture, BASE_TIME + 20_000).await?;
        let provider_observed_at = BASE_TIME + 20_100;
        let released_at = BASE_TIME + 20_200;
        let handoff_release = sqlx::query(
            "UPDATE github_server_service_authority_handoffs \
             SET released_at_ms = $2 WHERE id = $1 AND released_at_ms IS NULL",
        )
        .bind(attempt.handoff_id.as_uuid())
        .bind(released_at)
        .execute(database.pool())
        .await?;
        assert_eq!(handoff_release.rows_affected(), 1);
        let request = finalization(&fixture, attempt, provider_observed_at, released_at, false)?;
        let observation = request.observation().clone();
        let rejected_observation_id = observation.candidate().observation_id().as_uuid();
        let recorded_at = observation.candidate().expires_at().get() - 1;
        set_database_test_clock(&database, recorded_at).await?;

        let mut manifest_lock = database.pool().begin().await?;
        sqlx::query(
            "SELECT provider_connection_id FROM github_provider_manifest_current \
             WHERE tenant_id = $1 AND repository_id = $2 \
               AND provider_connection_id = $3 FOR UPDATE",
        )
        .bind(fixture.manifest.tenant().as_str())
        .bind(fixture.manifest.repository_id().as_uuid())
        .bind(fixture.manifest.connection_id().as_uuid())
        .fetch_one(&mut *manifest_lock)
        .await?;
        let mut observation_connection = database.pool().acquire().await?;
        let observation_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *observation_connection)
            .await?;
        let observation_task = tokio::spawn(async move {
            insert_workflow_permission_observation(
                &mut observation_connection,
                &observation,
                recorded_at,
            )
            .await
        });
        wait_for_backend_lock(database.pool(), observation_backend_pid).await?;
        set_database_test_clock(&database, recorded_at + 2).await?;
        manifest_lock.rollback().await?;
        let observation_error = observation_task
            .await?
            .expect_err("a matching observation waiting through expiry must fail closed");
        assert_constraint(
            &observation_error,
            "github_workflow_permission_activation_exact",
        );
        let observation_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_workflow_permission_default_observations \
             WHERE observation_id = $1",
        )
        .bind(rejected_observation_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(observation_count, 0);
        Ok(())
    })
    .await
}

async fn install_database_test_clock(database: &TestDatabase, now_ms: i64) -> TestResult {
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(database.pool())
        .await?;
    if !schema
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("test schema contains a non-identifier byte".into());
    }
    let schema = format!("\"{schema}\"");
    sqlx::query(AssertSqlSafe(format!(
        "CREATE TABLE IF NOT EXISTS {schema}.github_workflow_permission_test_clock (\
         singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), \
         now_ms BIGINT NOT NULL CHECK (now_ms >= 0))"
    )))
    .execute(database.pool())
    .await?;
    sqlx::query(AssertSqlSafe(format!(
        "INSERT INTO {schema}.github_workflow_permission_test_clock (singleton, now_ms) \
         VALUES (TRUE, $1) ON CONFLICT (singleton) DO UPDATE SET now_ms = EXCLUDED.now_ms"
    )))
    .bind(now_ms)
    .execute(database.pool())
    .await?;
    sqlx::query(AssertSqlSafe(format!(
        "CREATE OR REPLACE FUNCTION {schema}.clock_timestamp() RETURNS TIMESTAMPTZ \
         LANGUAGE SQL VOLATILE AS $clock$ \
         SELECT TIMESTAMPTZ 'epoch' + now_ms * INTERVAL '1 millisecond' \
         FROM {schema}.github_workflow_permission_test_clock WHERE singleton \
         $clock$"
    )))
    .execute(database.pool())
    .await?;
    set_database_test_clock(database, now_ms).await
}

async fn set_database_test_clock(database: &TestDatabase, now_ms: i64) -> TestResult {
    let updated =
        sqlx::query("UPDATE github_workflow_permission_test_clock SET now_ms = $1 WHERE singleton")
            .bind(now_ms)
            .execute(database.pool())
            .await?;
    assert_eq!(updated.rows_affected(), 1);
    let observed: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?;
    assert_eq!(observed, now_ms);
    Ok(())
}

async fn assert_workflow_permission_migration_catalog(database: &TestDatabase) -> TestResult {
    let migrated: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 28 AND success)",
    )
    .fetch_one(database.pool())
    .await?;
    assert!(migrated, "migration 0028 must be recorded as successful");

    let relations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_class AS relation \
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
         WHERE namespace.nspname = current_schema() \
           AND relation.relname = ANY($1::TEXT[])",
    )
    .bind([
        "github_workflow_permission_observation_candidates",
        "github_workflow_permission_default_observations",
        "github_workflow_permission_candidate_closures",
        "github_workflow_permission_default_heads",
    ])
    .fetch_one(database.pool())
    .await?;
    assert_eq!(relations, 4);

    let triggers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_trigger \
         WHERE NOT tgisinternal AND tgname = ANY($1::TEXT[])",
    )
    .bind([
        "github_workflow_permission_candidates_insert_guard",
        "github_workflow_permission_observations_insert_guard",
        "github_workflow_permission_closures_insert_guard",
        "github_workflow_permission_default_heads_write_guard",
        "logical_workflow_runtime_policy_pins_01_permission_defaults",
        "github_server_service_workflow_permission_handoff_insert_guard",
    ])
    .fetch_one(database.pool())
    .await?;
    assert_eq!(triggers, 6);
    Ok(())
}

fn tenant(label: &str) -> TestResult<TenantScope> {
    Ok(TenantScope::from_authenticated_tenant_id(format!(
        "{label}-{}",
        Uuid::new_v4().simple()
    ))?)
}

fn manifest(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    revision: u64,
) -> TestResult<GithubProviderManifest> {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(revision);
    Ok(GithubProviderManifest::new(
        tenant,
        connection,
        ProviderInstallationId::new(INSTALLATION_ID)?,
        ProviderRepositoryId::new(GITHUB_REPOSITORY_ID)?,
        GithubRepositoryName::new("automata-ci/workflow-permissions")?,
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(APP_ID)?,
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766")?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x11; 32]),
        GithubServerServiceRevision::new(revision)?,
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes(
            [0x22; 32],
        ))?,
        GithubServerServiceRevision::new(1)?,
        GithubServerServiceRevision::new(revision)?,
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI")?,
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(revision)?,
    ))
}

async fn prepare_revision(
    database: &TestDatabase,
    tenant: TenantScope,
    connection: ProviderConnectionId,
    revision: u64,
    now_ms: i64,
) -> TestResult<RevisionFixture> {
    set_database_test_clock(database, now_ms).await?;
    let manifest = manifest(tenant, connection, revision)?;
    let bootstrap = github_manifest_fixture::fixture_github_repository_bootstrap(
        manifest.clone(),
        UnixMillis::new(now_ms),
    );
    database
        .store()
        .prepare_github_workflow_permission_target(&manifest)
        .await?;
    let authority = GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::new_v4())?,
        manifest.repository_id(),
        manifest.connection_id(),
        manifest.installation_id(),
        manifest.github_app_id(),
        manifest.github_repository_id(),
        manifest.github_repository_name().clone(),
        GithubServerServiceScope::WorkflowPermissionsRead,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
        Sha256Digest::from_bytes([u8::try_from(revision)?; 32]),
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            authority.clone(),
            UnixMillis::new(now_ms),
        )?)
        .await?;
    mint_ready(database, &authority, now_ms + 100).await?;
    Ok(RevisionFixture {
        manifest,
        bootstrap,
        authority,
    })
}

async fn mint_ready(
    database: &TestDatabase,
    authority: &GithubServerServiceAuthorityIdentity,
    requested_at: i64,
) -> TestResult {
    let claim_expires_at = requested_at + 20_000;
    set_database_test_clock(database, requested_at).await?;
    let outcome = database
        .store()
        .claim_next_github_server_service_maintenance(
            ClaimNextGithubServerServiceMaintenance::for_authority(
                selector(authority),
                GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                UnixMillis::new(requested_at),
                UnixMillis::new(claim_expires_at),
            )?,
        )
        .await?;
    let Some(GithubServerServiceMaintenanceOutcome::Mint(claimed)) = outcome else {
        panic!("expected exact authority mint maintenance claim");
    };
    let claimed = *claimed;
    let generation = claimed.receipt().key().generation();
    let request_deadline = claimed.receipt().request_deadline().get();
    set_database_test_clock(database, requested_at + 1).await?;
    database
        .store()
        .begin_github_server_service_mint(BeginGithubServerServiceMint::new(
            &claimed,
            UnixMillis::new(requested_at + 1),
        )?)
        .await?;
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        authority.clone(),
        generation,
        UnixMillis::new(requested_at),
        UnixMillis::new(request_deadline),
        UnixMillis::new(requested_at + 3_600_000),
        32,
        Sha256Digest::from_bytes([0x33; 32]),
    )?;
    let protected = ProtectedGithubServerServiceCredential::new(
        metadata,
        EncryptedEnvelope::from_parts(
            1,
            WrappedDataKey::new(KeyId::new("workflow-permission-test-key")?, vec![0x44; 48])?,
            [0x55; 12],
            vec![0x66; 48],
        )?,
    )?;
    set_database_test_clock(database, requested_at + 2).await?;
    let receipt = database
        .store()
        .finish_github_server_service_mint(&FinishGithubServerServiceMint::ready(
            claimed.claim().clone(),
            protected,
            UnixMillis::new(requested_at + 2),
        )?)
        .await?;
    assert_eq!(receipt.key().generation(), generation);
    Ok(())
}

fn candidate(
    fixture: &RevisionFixture,
    claimed_at: i64,
) -> TestResult<GithubWorkflowPermissionObservationCandidate> {
    Ok(GithubWorkflowPermissionObservationCandidate::new(
        &fixture.bootstrap,
        &fixture.authority,
        automata_ci_store::GithubServerServiceConsumerId::from_uuid(Uuid::new_v4())?,
        GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
        UnixMillis::new(claimed_at),
    )?)
}

async fn begin_observation(
    database: &TestDatabase,
    fixture: &RevisionFixture,
    claimed_at: i64,
) -> TestResult<ObservationAttempt> {
    let candidate = candidate(fixture, claimed_at)?;
    set_database_test_clock(database, claimed_at).await?;
    database
        .store()
        .claim_github_workflow_permission_observation(candidate.clone())
        .await?;
    let proposed_handoff_id = GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?;
    let handoff = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            selector(&fixture.authority),
            proposed_handoff_id,
            candidate.consumer(),
            candidate.claimed_at(),
            UnixMillis::new(claimed_at + 300_000),
        )?)
        .await?;
    assert_eq!(handoff.handoff_id(), proposed_handoff_id);
    Ok(ObservationAttempt {
        candidate,
        handoff_id: handoff.handoff_id(),
        generation: handoff.receipt().key().generation(),
    })
}

fn finalization(
    fixture: &RevisionFixture,
    attempt: ObservationAttempt,
    provider_observed_at: i64,
    released_at: i64,
    mismatch_pull_request_approval: bool,
) -> TestResult<FinalizeGithubWorkflowPermissionObservation> {
    let release = ReleaseGithubServerServiceHandoff::new(
        selector(&fixture.authority),
        attempt.handoff_id,
        attempt.candidate.consumer(),
        UnixMillis::new(released_at),
    )?;
    let default = attempt.candidate.expected_default();
    let observation = GithubWorkflowPermissionDefaultsObservation::new(
        &fixture.bootstrap,
        attempt.candidate,
        &release,
        attempt.generation,
        default,
        mismatch_pull_request_approval,
        UnixMillis::new(provider_observed_at),
    )?;
    Ok(FinalizeGithubWorkflowPermissionObservation::new(
        fixture.bootstrap.clone(),
        release,
        observation,
    )?)
}

async fn finalize_matching(
    database: &TestDatabase,
    fixture: &RevisionFixture,
    claimed_at: i64,
    provider_observed_at: i64,
) -> TestResult {
    let attempt = begin_observation(database, fixture, claimed_at).await?;
    let request = finalization(
        fixture,
        attempt,
        provider_observed_at,
        provider_observed_at + 1,
        false,
    )?;
    set_database_test_clock(database, provider_observed_at + 1).await?;
    assert!(
        database
            .store()
            .finalize_github_workflow_permission_observation(request)
            .await?
    );
    Ok(())
}

async fn assert_head(
    database: &TestDatabase,
    fixture: &RevisionFixture,
    observation_id: Uuid,
    status: &str,
    provider_observed_at: i64,
) -> TestResult {
    let head: (Uuid, String, i64, i64, i64, Vec<u8>) = sqlx::query_as(
        "SELECT observation_id, status, provider_observed_at_ms, fresh_through_ms, \
                manifest_revision, runtime_policy_digest \
         FROM github_workflow_permission_default_heads \
         WHERE tenant_id = $1 AND repository_id = $2 AND provider_connection_id = $3",
    )
    .bind(fixture.manifest.tenant().as_str())
    .bind(fixture.manifest.repository_id().as_uuid())
    .bind(fixture.manifest.connection_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(head.0, observation_id);
    assert_eq!(head.1, status);
    assert_eq!(head.2, provider_observed_at);
    assert_eq!(head.4, i64::try_from(fixture.manifest.revision().get())?);
    assert_eq!(head.5, fixture.manifest.runtime_policy_digest().as_bytes());
    let expected_fresh_through = if status == "ready" {
        provider_observed_at + GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS
    } else {
        provider_observed_at
    };
    assert_eq!(head.3, expected_fresh_through);
    Ok(())
}

fn selector(
    authority: &GithubServerServiceAuthorityIdentity,
) -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_identity(authority)
}

async fn wait_for_backend_lock(pool: &PgPool, backend_pid: i32) -> TestResult {
    timeout(Duration::from_secs(5), async {
        loop {
            let waiting: Option<bool> = sqlx::query_scalar(
                "SELECT COALESCE(wait_event_type = 'Lock', FALSE) \
                 FROM pg_catalog.pg_stat_activity WHERE pid = $1",
            )
            .bind(backend_pid)
            .fetch_optional(pool)
            .await?;
            if waiting == Some(true) {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn insert_workflow_permission_candidate(
    connection: &mut PgConnection,
    candidate: &GithubWorkflowPermissionObservationCandidate,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let consumer = candidate.consumer();
    sqlx::query(
        r"
        INSERT INTO github_workflow_permission_observation_candidates (
            observation_id, tenant_id, repository_id, provider_connection_id,
            proposed_manifest_revision, proposed_manifest_digest,
            proposed_runtime_policy_revision, proposed_runtime_policy_digest,
            provider_installation_id, github_repository_id, github_repository_name,
            github_app_id, github_app_client_id, github_app_jwt_issuer_kind,
            app_key_spki_sha256, app_configuration_revision, policy_revision,
            authority_id, authority_identity_digest, expected_default,
            expected_can_approve_pull_request_reviews,
            consumer_owner_id, consumer_claim_fence, consumer_action,
            consumer_revision, claimed_at_ms, expires_at_ms, candidate_digest
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28
        )
        ",
    )
    .bind(candidate.observation_id().as_uuid())
    .bind(candidate.tenant().as_str())
    .bind(candidate.repository_id().as_uuid())
    .bind(candidate.connection_id().as_uuid())
    .bind(db_bigint(candidate.manifest_revision().get())?)
    .bind(candidate.manifest_digest().as_bytes().as_slice())
    .bind(db_bigint(candidate.runtime_policy_revision().get())?)
    .bind(candidate.runtime_policy_digest().as_bytes().as_slice())
    .bind(db_bigint(candidate.installation_id().get())?)
    .bind(db_bigint(candidate.github_repository_id().get())?)
    .bind(candidate.github_repository_name().as_str())
    .bind(db_bigint(candidate.github_app_id().get())?)
    .bind(candidate.github_app_client_id().as_str())
    .bind(candidate.github_app_jwt_issuer().as_str())
    .bind(candidate.app_key_spki_sha256().as_bytes().as_slice())
    .bind(db_bigint(candidate.app_configuration_revision().get())?)
    .bind(db_bigint(candidate.policy_revision().get())?)
    .bind(candidate.authority_selector().authority_id().as_uuid())
    .bind(candidate.authority_identity_digest().as_bytes().as_slice())
    .bind(candidate.expected_default().as_str())
    .bind(candidate.expected_can_approve_pull_request_reviews())
    .bind(consumer.owner().as_uuid())
    .bind(db_bigint(consumer.fence().get())?)
    .bind(consumer.action().as_str())
    .bind(db_bigint(consumer.revision().get())?)
    .bind(candidate.claimed_at().get())
    .bind(candidate.expires_at().get())
    .bind(candidate.digest().as_bytes().as_slice())
    .execute(connection)
    .await
}

async fn insert_workflow_permission_handoff(
    connection: &mut PgConnection,
    handoff_id: GithubServerServiceHandoffId,
    generation: GithubServerServiceGeneration,
    candidate: &GithubWorkflowPermissionObservationCandidate,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let consumer = candidate.consumer();
    sqlx::query(
        r"
        INSERT INTO github_server_service_authority_handoffs (
            id, tenant_id, authority_id, generation, consumer_id,
            consumer_owner_id, consumer_claim_fence, consumer_action,
            consumer_revision, required_through_ms, granted_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ",
    )
    .bind(handoff_id.as_uuid())
    .bind(candidate.tenant().as_str())
    .bind(candidate.authority_selector().authority_id().as_uuid())
    .bind(db_bigint(generation.get())?)
    .bind(candidate.observation_id().as_uuid())
    .bind(consumer.owner().as_uuid())
    .bind(db_bigint(consumer.fence().get())?)
    .bind(consumer.action().as_str())
    .bind(db_bigint(consumer.revision().get())?)
    .bind(candidate.claimed_at().get() + 300_000)
    .bind(candidate.claimed_at().get())
    .execute(connection)
    .await
}

async fn insert_workflow_permission_observation(
    connection: &mut PgConnection,
    observation: &GithubWorkflowPermissionDefaultsObservation,
    recorded_at: i64,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let candidate = observation.candidate();
    let matches = observation.matches_expected_default();
    sqlx::query(
        r"
        INSERT INTO github_workflow_permission_default_observations (
            observation_id, tenant_id, repository_id, provider_connection_id,
            candidate_digest, handoff_id, handoff_generation,
            default_workflow_permissions, can_approve_pull_request_reviews,
            matches_expected_default, api_version, request_started_at_ms,
            provider_observed_at_ms, released_at_ms, recorded_at_ms,
            activated_manifest_revision, activated_manifest_digest,
            activated_runtime_policy_revision, activated_runtime_policy_digest,
            observation_digest
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
        )
        ",
    )
    .bind(candidate.observation_id().as_uuid())
    .bind(candidate.tenant().as_str())
    .bind(candidate.repository_id().as_uuid())
    .bind(candidate.connection_id().as_uuid())
    .bind(candidate.digest().as_bytes().as_slice())
    .bind(observation.handoff_id().as_uuid())
    .bind(db_bigint(observation.handoff_generation().get())?)
    .bind(observation.default_workflow_permissions().as_str())
    .bind(observation.can_approve_pull_request_reviews())
    .bind(matches)
    .bind(automata_ci_store::GITHUB_PROVIDER_REST_API_VERSION)
    .bind(candidate.claimed_at().get())
    .bind(observation.provider_observed_at().get())
    .bind(observation.released_at().get())
    .bind(recorded_at)
    .bind(
        matches
            .then(|| db_bigint(candidate.manifest_revision().get()))
            .transpose()?,
    )
    .bind(matches.then(|| candidate.manifest_digest().as_bytes().to_vec()))
    .bind(
        matches
            .then(|| db_bigint(candidate.runtime_policy_revision().get()))
            .transpose()?,
    )
    .bind(matches.then(|| candidate.runtime_policy_digest().as_bytes().to_vec()))
    .bind(observation.digest().as_bytes().as_slice())
    .execute(connection)
    .await
}

fn db_bigint(value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value).map_err(invalid_sql_binding)
}

fn invalid_sql_binding(error: impl std::fmt::Display) -> sqlx::Error {
    sqlx::Error::Protocol(error.to_string())
}

async fn clone_candidate_with_digest(
    database: &TestDatabase,
    source_id: Uuid,
    clone_id: Uuid,
    digest: Option<&[u8]>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        r"
        INSERT INTO github_workflow_permission_observation_candidates (
            observation_id, tenant_id, repository_id, provider_connection_id,
            proposed_manifest_revision, proposed_manifest_digest,
            proposed_runtime_policy_revision, proposed_runtime_policy_digest,
            provider_installation_id, github_repository_id, github_repository_name,
            github_app_id, github_app_client_id, github_app_jwt_issuer_kind,
            app_key_spki_sha256, app_configuration_revision, policy_revision,
            authority_id, authority_identity_digest, expected_default,
            expected_can_approve_pull_request_reviews,
            consumer_owner_id, consumer_claim_fence, consumer_action,
            consumer_revision, claimed_at_ms, expires_at_ms, candidate_digest
        )
        SELECT $2, tenant_id, repository_id, provider_connection_id,
               proposed_manifest_revision, proposed_manifest_digest,
               proposed_runtime_policy_revision, proposed_runtime_policy_digest,
               provider_installation_id, github_repository_id, github_repository_name,
               github_app_id, github_app_client_id, github_app_jwt_issuer_kind,
               app_key_spki_sha256, app_configuration_revision, policy_revision,
               authority_id, authority_identity_digest, expected_default,
               expected_can_approve_pull_request_reviews,
               consumer_owner_id, consumer_claim_fence, consumer_action,
               consumer_revision, claimed_at_ms, expires_at_ms, $3
        FROM github_workflow_permission_observation_candidates
        WHERE observation_id = $1
        ",
    )
    .bind(source_id)
    .bind(clone_id)
    .bind(digest)
    .execute(database.pool())
    .await
}

async fn disable_pin_provenance(transaction: &mut Transaction<'_, Postgres>) -> TestResult {
    sqlx::query(
        "ALTER TABLE logical_workflow_runtime_policy_pins \
         DISABLE TRIGGER logical_workflow_runtime_policy_pins_00_provenance",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_policy_pin(
    transaction: &mut Transaction<'_, Postgres>,
    fixture: &RevisionFixture,
    revision: i64,
    digest: &[u8],
    pinned_at: i64,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO logical_workflow_runtime_policy_pins (\
             run_id, tenant_id, repository_id, policy_revision, policy_digest, pinned_at_ms\
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.manifest.tenant().as_str())
    .bind(fixture.manifest.repository_id().as_uuid())
    .bind(revision)
    .bind(digest)
    .bind(pinned_at)
    .execute(&mut **transaction)
    .await
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some(expected),
        "unexpected database error: {error}"
    );
}
