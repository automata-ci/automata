use crate::github_manifest_fixture;

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_key_management::{EncryptedEnvelope, KeyId, WrappedDataKey};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AcquireGithubServerServiceHandoff,
    AdmissionObject, BeginGithubServerServiceMint, BindGithubCheckSuite,
    ClaimGithubCheckProjection, ClaimNextGithubServerServiceMaintenance, ClaimProviderDelivery,
    EnsureGithubServerServiceAuthority, FinishGithubServerServiceMint,
    FinishGithubServerServiceRevocation, GITHUB_SERVICE_FAILURE_BUDGET_REARM_MILLIS,
    GithubCheckHeadSha, GithubCheckName, GithubCheckProjectionAction,
    GithubCheckProjectionOutbox as _, GithubCheckProjectionWorkerId, GithubCheckSuiteId,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAction,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository as _,
    GithubServerServiceAuthoritySelector, GithubServerServiceAuthorityState,
    GithubServerServiceClaimFence, GithubServerServiceConsumerClaim, GithubServerServiceConsumerId,
    GithubServerServiceEnvelopeMetadata, GithubServerServiceFailureKind,
    GithubServerServiceGeneration, GithubServerServiceHandoffId, GithubServerServiceIssuanceKey,
    GithubServerServiceIssuanceState, GithubServerServiceJwtIssuer,
    GithubServerServiceMaintenanceOutcome, GithubServerServiceRevision, GithubServerServiceScope,
    GithubServerServiceStoreError, GithubServerServiceWorkerId,
    GithubSubjectEvidenceRepository as _, MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS, ObjectKey,
    ProtectedGithubServerServiceCredential, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryClaimRenewalRepository as _, ProviderDeliveryIdentity,
    ProviderDeliveryRenewalTiming, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, QuarantineGithubServerServiceCredential,
    ReleaseGithubServerServiceHandoff, RenewProviderDeliveryClaim, RepositoryId,
    RetireGithubServerServiceAuthority, TenantScope,
};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::support::{TestDatabase, TestResult, run_with_database};

const INSTALLATION_ID: u64 = 101;
const GITHUB_REPOSITORY_ID: u64 = 202;
const APP_ID: u64 = 303;
const EVIDENCE_OWNER_ID: u64 = 404;
const EVIDENCE_APP_CONFIGURATION_REVISION: u64 = 10_000;

#[derive(Debug)]
struct LifecycleScenario {
    authority: GithubServerServiceAuthorityIdentity,
    consumer: GithubServerServiceConsumerClaim,
    handoff_id: GithubServerServiceHandoffId,
}

/// Installs a schema-local `PostgreSQL` clock used only by this test database.
///
/// Every production authority decision still calls `PostgreSQL`
/// `clock_timestamp()` after its locks. Making that function schema-local lets
/// these lifecycle tests cross multi-minute failure and erasure horizons
/// deterministically without restoring caller-clock authority or sleeping for
/// real minutes.
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
        "CREATE TABLE IF NOT EXISTS {schema}.github_service_test_clock (\
         singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), \
         now_ms BIGINT NOT NULL CHECK (now_ms >= 0))"
    )))
    .execute(database.pool())
    .await?;
    sqlx::query(AssertSqlSafe(format!(
        "INSERT INTO {schema}.github_service_test_clock (singleton, now_ms) \
         VALUES (TRUE, $1) ON CONFLICT (singleton) DO UPDATE SET now_ms = EXCLUDED.now_ms"
    )))
    .bind(now_ms)
    .execute(database.pool())
    .await?;
    sqlx::query(AssertSqlSafe(format!(
        "CREATE OR REPLACE FUNCTION {schema}.clock_timestamp() RETURNS TIMESTAMPTZ \
         LANGUAGE SQL VOLATILE AS $clock$ \
         SELECT TIMESTAMPTZ 'epoch' + now_ms * INTERVAL '1 millisecond' \
         FROM {schema}.github_service_test_clock WHERE singleton \
         $clock$"
    )))
    .execute(database.pool())
    .await?;

    set_database_test_clock(database, now_ms).await
}

async fn set_database_test_clock(database: &TestDatabase, now_ms: i64) -> TestResult {
    let updated = sqlx::query("UPDATE github_service_test_clock SET now_ms = $1 WHERE singleton")
        .bind(now_ms)
        .execute(database.pool())
        .await?;
    if updated.rows_affected() != 1 {
        return Err("test database clock is not installed".into());
    }
    let observed: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?;
    if observed != now_ms {
        return Err(
            format!("test database clock mismatch: expected {now_ms}, got {observed}").into(),
        );
    }
    Ok(())
}

async fn assert_database_test_clock_survives_connection_replacement(
    database: &TestDatabase,
    now_ms: i64,
) -> TestResult {
    set_database_test_clock(database, now_ms).await?;
    let pool = database.pool();
    let maximum_connections = pool.options().get_max_connections();
    let mut held = Vec::with_capacity(usize::try_from(maximum_connections)?);
    for _ in 0..maximum_connections {
        held.push(pool.acquire().await?);
    }

    let mut retired = held.pop().ok_or("test pool has no connections")?;
    let retired_process_id: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *retired)
        .await?;
    retired.close().await?;

    let mut replacement = pool.acquire().await?;
    let (replacement_process_id, observed): (i32, i64) = sqlx::query_as(
        "SELECT pg_backend_pid(), \
         floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(&mut *replacement)
    .await?;
    assert_ne!(replacement_process_id, retired_process_id);
    assert_eq!(observed, now_ms);
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn exact_revisions_overlap_while_same_revision_and_retirement_stay_isolated() -> TestResult {
    run_with_database(|database| async move {
        assert_revision_overlap_catalog(&database).await?;
        let fixture = seed_fixture(&database, "revision-overlap", 100).await?;
        let revision_7 = revision_overlap_identity(&fixture, Uuid::new_v4(), 7, 7, 0x41)?;
        insert_authority_direct(&database, &revision_7, 100).await?;

        let same_revision = revision_overlap_identity(&fixture, Uuid::new_v4(), 7, 7, 0x42)?;
        let error = insert_authority_direct(&database, &same_revision, 101)
            .await
            .expect_err("one repository scope revision has one exact authority");
        assert_unique_constraint(
            &error,
            "github_server_service_authorities_repository_scope_revision_uni",
        );

        let next_policy = revision_overlap_identity(&fixture, Uuid::new_v4(), 7, 8, 0x41)?;
        insert_authority_direct(&database, &next_policy, 102).await?;
        let revision_8 = revision_overlap_identity(&fixture, Uuid::new_v4(), 8, 8, 0x41)?;
        insert_authority_direct(&database, &revision_8, 103).await?;
        assert_revision_lock_isolation(&database, &revision_7, &revision_8).await?;

        let active_configurations: (i64, i64) = sqlx::query_as(
            "SELECT count(*), count(DISTINCT configuration_fingerprint) \
             FROM github_server_service_authorities \
             WHERE id IN ($1, $2, $3) AND state = 'active'",
        )
        .bind(revision_7.authority_id().as_uuid())
        .bind(next_policy.authority_id().as_uuid())
        .bind(revision_8.authority_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            active_configurations,
            (3, 1),
            "App and policy revisions may overlap with one config-only fingerprint"
        );

        set_database_test_clock(&database, 200).await?;
        let retired = database
            .store()
            .retire_github_server_service_authority(RetireGithubServerServiceAuthority::new(
                GithubServerServiceAuthoritySelector::from_identity(&revision_7),
                UnixMillis::new(200),
            )?)
            .await?;
        assert_eq!(retired.identity(), &revision_7);
        assert_eq!(retired.state(), GithubServerServiceAuthorityState::Retired);
        let exact_states: (bool, bool, bool) = sqlx::query_as(
            "SELECT \
                 EXISTS (SELECT 1 FROM github_server_service_authorities \
                         WHERE id = $1 AND state = 'retired'), \
                 EXISTS (SELECT 1 FROM github_server_service_authorities \
                         WHERE id = $2 AND state = 'active'), \
                 EXISTS (SELECT 1 FROM github_server_service_authorities \
                         WHERE id = $3 AND state = 'active')",
        )
        .bind(revision_7.authority_id().as_uuid())
        .bind(next_policy.authority_id().as_uuid())
        .bind(revision_8.authority_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(exact_states, (true, true, true));

        let retired_revision_reuse =
            revision_overlap_identity(&fixture, Uuid::new_v4(), 7, 7, 0x43)?;
        let error = insert_authority_direct(&database, &retired_revision_reuse, 201)
            .await
            .expect_err("retirement cannot free immutable revision identity");
        assert_unique_constraint(
            &error,
            "github_server_service_authorities_repository_scope_revision_uni",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn maintenance_bootstraps_and_recovers_generation_after_lost_claim() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(&database, "maintenance-restart", 10).await?;
        let identity = ensure_authority(
            &database,
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            Uuid::new_v4(),
            100,
        )
        .await?;
        let first = claim_next_maintenance(&database, &fixture.tenant, 200, 300)
            .await?
            .expect("bootstrap mint claim");
        let first_key = match first {
            GithubServerServiceMaintenanceOutcome::Mint(claimed) => claimed.claim().key(),
            _ => panic!("bootstrap must reserve a mint generation"),
        };
        assert_eq!(
            first_key.generation(),
            GithubServerServiceGeneration::new(1)?
        );
        let descriptor = database
            .store()
            .inspect_github_server_service_authority(identity.tenant(), identity.authority_id())
            .await?;
        assert_eq!(
            descriptor.refresh_generation(),
            Some(first_key.generation())
        );
        assert_eq!(
            descriptor.next_generation(),
            GithubServerServiceGeneration::new(2)?
        );

        let live = claim_next_maintenance(&database, &fixture.tenant, 299, 399).await?;
        assert!(live.is_none(), "a live lost claim must not be duplicated");

        let reduced = claim_next_maintenance(&database, &fixture.tenant, 300, 400)
            .await?
            .expect("expired lost claim reduction");
        assert!(matches!(
            reduced,
            GithubServerServiceMaintenanceOutcome::Reduced { receipt, .. }
                if receipt.state() == GithubServerServiceIssuanceState::Rejected
        ));

        let backoff = claim_next_maintenance(&database, &fixture.tenant, 301, 401).await?;
        assert!(
            backoff.is_none(),
            "failed history must enforce its mint gate"
        );
        let descriptor = database
            .store()
            .inspect_github_server_service_authority(identity.tenant(), identity.authority_id())
            .await?;
        assert_eq!(
            descriptor.next_mint_not_before(),
            Some(UnixMillis::new(60_300))
        );
        assert_eq!(
            descriptor.mint_gate_generation(),
            Some(GithubServerServiceGeneration::new(1)?)
        );

        let replacement = claim_next_maintenance(&database, &fixture.tenant, 60_300, 60_400)
            .await?
            .expect("next generation after the exact failed-history gate");
        match replacement {
            GithubServerServiceMaintenanceOutcome::Mint(claimed) => assert_eq!(
                claimed.claim().key().generation(),
                GithubServerServiceGeneration::new(2)?
            ),
            _ => panic!("terminal history must advance to a fresh generation"),
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn production_sized_mint_retry_waits_for_deadline_reduction() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(&database, "maintenance-mint-retry", 10).await?;
        let identity = ensure_authority(
            &database,
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            Uuid::new_v4(),
            100,
        )
        .await?;
        let requested_at = 1_000;
        let request_deadline = requested_at + MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS;
        let key = GithubServerServiceIssuanceKey::new(
            identity.authority_id(),
            GithubServerServiceGeneration::new(1)?,
        );
        let claimed = claim_next_mint(
            &database,
            &identity,
            key.generation(),
            requested_at,
            request_deadline,
        )
        .await?;

        set_database_test_clock(&database, 1_050).await?;
        database
            .store()
            .begin_github_server_service_mint(BeginGithubServerServiceMint::new(
                &claimed,
                UnixMillis::new(1_050),
            )?)
            .await?;
        let retry_at = 1_200;
        set_database_test_clock(&database, 1_100).await?;
        let pending = database
            .store()
            .finish_github_server_service_mint(&FinishGithubServerServiceMint::retry(
                claimed.claim().clone(),
                GithubServerServiceFailureKind::new("provider_unavailable")?,
                UnixMillis::new(1_100),
                UnixMillis::new(retry_at),
            )?)
            .await?;
        assert_eq!(pending.key(), key);
        assert_eq!(
            pending.state(),
            GithubServerServiceIssuanceState::MintRetryPending
        );
        assert_eq!(
            pending.request_deadline(),
            UnixMillis::new(request_deadline)
        );
        assert_eq!(pending.mint_attempts(), 1);

        let retry = claim_next_maintenance(
            &database,
            identity.tenant(),
            retry_at,
            retry_at + MAX_GITHUB_SERVICE_REVOKE_CLAIM_MILLIS,
        )
        .await?;
        assert!(
            retry.is_none(),
            "a second production-sized claim cannot fit the original request deadline"
        );
        assert_issuance_state(&database, key, "mint_retry").await?;

        let reduced = claim_next_reduced(
            &database,
            &identity,
            key,
            request_deadline,
            request_deadline + 100,
            GithubServerServiceIssuanceState::Rejected,
        )
        .await?;
        assert_eq!(reduced.mint_attempts(), 1);
        let already_reduced = claim_next_maintenance(
            &database,
            identity.tenant(),
            request_deadline + 1,
            request_deadline + 101,
        )
        .await?;
        assert!(
            already_reduced.is_none(),
            "the terminal retry reduction must not be replayed as maintenance"
        );
        assert_issuance_state(&database, key, "rejected").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn maintenance_skip_locked_makes_progress_on_the_next_authority() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(&database, "maintenance-skip-locked", 10).await?;
        let first = ensure_authority(
            &database,
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            Uuid::from_u128(1),
            100,
        )
        .await?;
        let second_repository_uuid = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'github', '203', 'automata-ci', 'automata-two', 1, 1)
            ",
        )
        .bind(second_repository_uuid)
        .bind(fixture.tenant.as_str())
        .execute(database.pool())
        .await?;
        let second = GithubServerServiceAuthorityIdentity::new(
            fixture.tenant.clone(),
            GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(2))?,
            RepositoryId::from_uuid(second_repository_uuid),
            fixture.connection_id,
            ProviderInstallationId::new(INSTALLATION_ID)?,
            GithubServerServiceAppId::new(APP_ID)?,
            ProviderRepositoryId::new(203)?,
            GithubRepositoryName::new("automata-ci/automata-two")?,
            GithubServerServiceScope::ChecksWrite,
            GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766")?,
            GithubServerServiceJwtIssuer::AppClientId,
            Sha256Digest::from_bytes([11; 32]),
            GithubServerServiceRevision::new(1)?,
            GithubServerServiceRevision::new(1)?,
            Sha256Digest::from_bytes([13; 32]),
        )?;
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                second.clone(),
                UnixMillis::new(101),
            )?)
            .await?;
        let mut blocker = database.pool().begin().await?;
        sqlx::query("SELECT id FROM github_server_service_authorities WHERE id = $1 FOR UPDATE")
            .bind(first.authority_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;

        set_database_test_clock(&database, 200).await?;
        let claimed = database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::new(
                    fixture.tenant.clone(),
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    UnixMillis::new(200),
                    UnixMillis::new(300),
                )?,
            )
            .await?
            .expect("unlocked authority must not starve");
        match claimed {
            GithubServerServiceMaintenanceOutcome::Mint(claimed) => {
                assert_eq!(claimed.claim().key().authority_id(), second.authority_id());
            }
            _ => panic!("unlocked bootstrap must be claimed"),
        }
        blocker.rollback().await?;

        set_database_test_clock(&database, 201).await?;
        let claimed = database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::new(
                    fixture.tenant.clone(),
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    UnixMillis::new(201),
                    UnixMillis::new(301),
                )?,
            )
            .await?
            .expect("previously locked authority remains discoverable");
        match claimed {
            GithubServerServiceMaintenanceOutcome::Mint(claimed) => {
                assert_eq!(claimed.claim().key().authority_id(), first.authority_id());
            }
            _ => panic!("released bootstrap must be claimed"),
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn maintenance_uses_the_bounded_head_after_more_than_sixty_four_retired_rows() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(&database, "maintenance-bounded-head", 10).await?;
        for ordinal in 0_u8..64 {
            let created_at = 100 + i64::from(ordinal) * 2;
            let identity = ensure_authority_with_app_configuration_revision(
                &database,
                &fixture,
                GithubServerServiceScope::ChecksWrite,
                Uuid::new_v4(),
                created_at,
                u64::from(ordinal) + 1,
                ordinal,
            )
            .await?;
            set_database_test_clock(&database, created_at + 1).await?;
            let retired = database
                .store()
                .retire_github_server_service_authority(RetireGithubServerServiceAuthority::new(
                    authority_selector(&identity),
                    UnixMillis::new(created_at + 1),
                )?)
                .await?;
            assert_eq!(retired.state(), GithubServerServiceAuthorityState::Retired);
        }
        let retired_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_server_service_authorities \
             WHERE tenant_id = $1 AND state = 'retired'",
        )
        .bind(fixture.tenant.as_str())
        .fetch_one(database.pool())
        .await?;
        assert!(
            retired_count > 64,
            "fixture must retain more than 64 retired rows"
        );
        let healthy = ensure_authority_with_app_configuration_revision(
            &database,
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            Uuid::new_v4(),
            1_000,
            66,
            65,
        )
        .await?;

        let mut plan_transaction = database.pool().begin().await?;
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *plan_transaction)
            .await?;
        let plan = sqlx::query_scalar::<_, String>(
            r"
            EXPLAIN (COSTS OFF)
            SELECT id, next_issuance_generation, state_updated_at_ms
            FROM github_server_service_authorities
            WHERE tenant_id = $1 AND state = 'active'
              AND current_issuance_generation IS NULL
              AND refresh_issuance_generation IS NULL
              AND state_updated_at_ms <= $2
            ORDER BY state_updated_at_ms, id, next_issuance_generation
            LIMIT 64
            ",
        )
        .bind(fixture.tenant.as_str())
        .bind(1_100_i64)
        .fetch_all(&mut *plan_transaction)
        .await?
        .join("\n");
        assert!(
            plan.contains("github_server_service_authorities_bootstrap_due"),
            "bounded bootstrap head must use its partial due index: {plan}"
        );
        plan_transaction.rollback().await?;

        set_database_test_clock(&database, 1_100).await?;
        let outcome = database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::new(
                    fixture.tenant.clone(),
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    UnixMillis::new(1_100),
                    UnixMillis::new(1_200),
                )?,
            )
            .await?
            .expect("healthy active head must remain discoverable");
        match outcome {
            GithubServerServiceMaintenanceOutcome::Mint(claimed) => {
                assert_eq!(claimed.claim().key().authority_id(), healthy.authority_id());
            }
            _ => panic!("healthy bootstrap head must be claimed"),
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One constrained fixture proves saturated-current quarantine atomically.
async fn saturated_failure_budget_still_quarantines_current() -> TestResult {
    run_with_database(|database| async move {
        let current_fixture = seed_fixture(&database, "failure-breaker-current", 10).await?;
        let current_identity = ensure_authority(
            &database,
            &current_fixture,
            GithubServerServiceScope::ChecksWrite,
            Uuid::new_v4(),
            100,
        )
        .await?;
        mint_ready(&database, &current_identity, 1, 100, 200, 150).await?;

        // A production-sized refresh window reaches the current credential's
        // safe-erasure boundary before 32 one-minute failure gates can elapse.
        // The adjacent rearm test exercises those 32 failures organically; this
        // fixture starts at the resulting constraint-valid saturated state so
        // this test can isolate quarantine of a still-current credential.
        let next_mint_not_before = 200;
        let mint_gate_generation = 1_u64;
        let failure_budget_rearm_at =
            next_mint_not_before + GITHUB_SERVICE_FAILURE_BUDGET_REARM_MILLIS;
        let mut saturated_setup = database.pool().begin().await?;
        sqlx::query(
            "ALTER TABLE github_server_service_authorities \
             DISABLE TRIGGER github_server_service_authorities_update_guard",
        )
        .execute(&mut *saturated_setup)
        .await?;
        let saturated = sqlx::query(
            r"
            UPDATE github_server_service_authorities
            SET consecutive_generation_failures = 32,
                next_mint_not_before_ms = $2,
                mint_gate_generation = $3,
                failure_budget_rearm_at_ms = $4,
                state_updated_at_ms = $2
            WHERE id = $1
              AND state = 'active'
              AND current_issuance_generation = 1
              AND refresh_issuance_generation IS NULL
              AND next_issuance_generation = 2
            ",
        )
        .bind(current_identity.authority_id().as_uuid())
        .bind(next_mint_not_before)
        .bind(i64::try_from(mint_gate_generation)?)
        .bind(failure_budget_rearm_at)
        .execute(&mut *saturated_setup)
        .await?;
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *saturated_setup)
            .await?;
        sqlx::query(
            "ALTER TABLE github_server_service_authorities \
             ENABLE TRIGGER github_server_service_authorities_update_guard",
        )
        .execute(&mut *saturated_setup)
        .await?;
        saturated_setup.commit().await?;
        assert_eq!(saturated.rows_affected(), 1);

        let before_quarantine = database
            .store()
            .inspect_github_server_service_authority(
                current_identity.tenant(),
                current_identity.authority_id(),
            )
            .await?;
        assert_eq!(before_quarantine.consecutive_generation_failures(), 32);
        assert_eq!(
            before_quarantine.current_generation(),
            Some(GithubServerServiceGeneration::new(1)?)
        );
        assert_eq!(
            before_quarantine.next_generation(),
            GithubServerServiceGeneration::new(2)?
        );
        assert_eq!(before_quarantine.refresh_generation(), None);
        assert_eq!(
            before_quarantine.next_mint_not_before(),
            Some(UnixMillis::new(next_mint_not_before))
        );
        assert_eq!(
            before_quarantine.mint_gate_generation(),
            Some(GithubServerServiceGeneration::new(mint_gate_generation)?)
        );
        assert_eq!(
            before_quarantine.failure_budget_rearm_at(),
            Some(UnixMillis::new(failure_budget_rearm_at))
        );
        let current_metadata = GithubServerServiceEnvelopeMetadata::new(
            current_identity.clone(),
            GithubServerServiceGeneration::new(1)?,
            UnixMillis::new(100),
            UnixMillis::new(200),
            UnixMillis::new(3_600_100),
            32,
            Sha256Digest::from_bytes([21; 32]),
        )?;
        let quarantined_at = 1_000;
        set_database_test_clock(&database, quarantined_at).await?;
        let quarantined = database
            .store()
            .quarantine_github_server_service_credential(
                QuarantineGithubServerServiceCredential::new(
                    authority_selector(&current_identity),
                    GithubServerServiceIssuanceKey::new(
                        current_identity.authority_id(),
                        GithubServerServiceGeneration::new(1)?,
                    ),
                    current_metadata.aad_digest(),
                    GithubServerServiceFailureKind::new("aad_corrupt")?,
                    UnixMillis::new(quarantined_at),
                )?,
            )
            .await?;
        assert_eq!(
            quarantined.state(),
            GithubServerServiceIssuanceState::Quarantined
        );
        let after_quarantine = database
            .store()
            .inspect_github_server_service_authority(
                current_identity.tenant(),
                current_identity.authority_id(),
            )
            .await?;
        assert_eq!(after_quarantine.consecutive_generation_failures(), 32);
        assert_eq!(after_quarantine.current_generation(), None);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn saturated_failure_budget_rearms_one_probationary_generation() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(&database, "failure-budget-rearm", 10).await?;
        let identity = ensure_authority(
            &database,
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            Uuid::new_v4(),
            100,
        )
        .await?;

        let mut requested_at = 1_000;
        let mut last_failure_at = 0;
        for generation in 1..=32 {
            let generation = GithubServerServiceGeneration::new(generation)?;
            let claimed = claim_next_mint(
                &database,
                &identity,
                generation,
                requested_at,
                requested_at + 500,
            )
            .await?;
            last_failure_at = requested_at + 500;
            claim_next_reduced(
                &database,
                &identity,
                claimed.claim().key(),
                last_failure_at,
                last_failure_at + 100,
                GithubServerServiceIssuanceState::Rejected,
            )
            .await?;
            requested_at = last_failure_at + 60_000;
        }

        let rearm_at = last_failure_at + GITHUB_SERVICE_FAILURE_BUDGET_REARM_MILLIS;
        let saturated = database
            .store()
            .inspect_github_server_service_authority(identity.tenant(), identity.authority_id())
            .await?;
        assert_eq!(saturated.consecutive_generation_failures(), 32);
        assert_eq!(
            saturated.failure_budget_rearm_at(),
            Some(UnixMillis::new(rearm_at))
        );
        set_database_test_clock(&database, rearm_at - 1).await?;
        assert!(
            database
                .store()
                .claim_next_github_server_service_maintenance(
                    ClaimNextGithubServerServiceMaintenance::new(
                        fixture.tenant.clone(),
                        GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                        UnixMillis::new(rearm_at - 1),
                        UnixMillis::new(rearm_at + 999),
                    )?,
                )
                .await?
                .is_none(),
            "the saturated authority must remain closed until the exact cooldown boundary"
        );

        set_database_test_clock(&database, rearm_at).await?;
        let resumed = database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::new(
                    fixture.tenant.clone(),
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    UnixMillis::new(rearm_at),
                    UnixMillis::new(rearm_at + 1_000),
                )?,
            )
            .await?
            .expect("the exact cooldown boundary must admit one probationary generation");
        match resumed {
            GithubServerServiceMaintenanceOutcome::Mint(claimed) => assert_eq!(
                claimed.claim().key().generation(),
                GithubServerServiceGeneration::new(33)?
            ),
            _ => panic!("failure-budget rearm must reserve a fresh generation"),
        }
        let probationary = database
            .store()
            .inspect_github_server_service_authority(identity.tenant(), identity.authority_id())
            .await?;
        assert_eq!(probationary.consecutive_generation_failures(), 31);
        assert_eq!(probationary.failure_budget_rearm_at(), None);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn current_refresh_handoff_revocation_and_retirement_are_fenced() -> TestResult {
    run_with_database(|database| async move {
        let scenario = prepare_lifecycle_scenario(&database).await?;

        rotate_lifecycle_authority(&database, &scenario).await?;

        release_and_revoke_previous(&database, &scenario).await?;

        retire_lifecycle_authority(&database, &scenario.authority).await?;

        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn handoff_replay_rejects_a_forward_protected_plaintext_schema() -> TestResult {
    run_with_database(|database| async move {
        let scenario = prepare_lifecycle_scenario(&database).await?;
        sqlx::query(
            r"
            ALTER TABLE github_server_service_authority_issuances
            DISABLE TRIGGER github_server_service_issuances_update_guard
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            ALTER TABLE github_server_service_authority_issuances
            DROP CONSTRAINT github_server_service_issuances_protected_shape
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE github_server_service_authority_issuances
            SET plaintext_schema = 2
            WHERE authority_id = $1 AND generation = 1
            ",
        )
        .bind(scenario.authority.authority_id().as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            ALTER TABLE github_server_service_authority_issuances
            ENABLE TRIGGER github_server_service_issuances_update_guard
            ",
        )
        .execute(database.pool())
        .await?;

        set_database_test_clock(&database, 2_201_100).await?;
        assert!(matches!(
            database
                .store()
                .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
                    authority_selector(&scenario.authority),
                    scenario.handoff_id,
                    scenario.consumer,
                    UnixMillis::new(2_201_100),
                    UnixMillis::new(2_500_000),
                )?,)
                .await,
            Err(GithubServerServiceStoreError::CorruptData)
        ));
        Ok(())
    })
    .await
}

async fn prepare_lifecycle_scenario(database: &TestDatabase) -> TestResult<LifecycleScenario> {
    let fixture = seed_fixture(database, "lifecycle", 10).await?;
    let ensure_claim = claim_check(database, &fixture, 2_000, 50_000).await?;
    assert_eq!(
        ensure_claim.action(),
        GithubCheckProjectionAction::EnsureSuite
    );
    database
        .store()
        .bind_github_check_suite(BindGithubCheckSuite::new(
            ensure_claim.claim(),
            GithubCheckSuiteId::new(401)?,
            UnixMillis::new(2_200),
        )?)
        .await?;
    let check_claim = claim_check(database, &fixture, 2_200_000, 2_300_000).await?;
    assert_eq!(
        check_claim.action(),
        GithubCheckProjectionAction::PrepareRunCreate
    );
    let authority = ensure_authority(
        database,
        &fixture,
        GithubServerServiceScope::ChecksWrite,
        Uuid::new_v4(),
        100,
    )
    .await?;
    mint_ready(database, &authority, 1, 1_000, 20_000, 1_100)
        .await
        .map_err(|error| format!("initial ready generation: {error}"))?;

    let consumer = check_consumer(&check_claim)?;
    let handoff_id = GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?;
    set_database_test_clock(database, 2_201_000).await?;
    let handoff = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            authority_selector(&authority),
            handoff_id,
            consumer,
            UnixMillis::new(2_201_000),
            UnixMillis::new(2_500_000),
        )?)
        .await
        .map_err(|error| format!("initial exact handoff: {error}"))?;
    assert_eq!(
        handoff.identity().github_repository_name().as_str(),
        "automata-ci/automata"
    );
    assert_eq!(
        handoff.receipt().state(),
        GithubServerServiceIssuanceState::Ready
    );
    Ok(LifecycleScenario {
        authority,
        consumer,
        handoff_id,
    })
}

async fn rotate_lifecycle_authority(
    database: &TestDatabase,
    scenario: &LifecycleScenario,
) -> TestResult {
    // Committing generation two atomically makes it current and moves the
    // prior current generation into revoke-only custody.
    mint_ready(
        database,
        &scenario.authority,
        2,
        2_221_000,
        2_241_000,
        2_221_100,
    )
    .await
    .map_err(|error| format!("refresh ready generation: {error}"))?;
    set_database_test_clock(database, 2_221_500).await?;
    let replayed = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            authority_selector(&scenario.authority),
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
            scenario.consumer,
            UnixMillis::new(2_221_500),
            UnixMillis::new(2_500_000),
        )?)
        .await
        .map_err(|error| format!("handoff replay after rotation: {error}"))?;
    assert_eq!(
        replayed.receipt().state(),
        GithubServerServiceIssuanceState::RevokePending
    );
    assert_eq!(replayed.acquired_at(), UnixMillis::new(2_221_500));
    assert_eq!(replayed.handoff_id(), scenario.handoff_id);

    let old_key = GithubServerServiceIssuanceKey::new(
        scenario.authority.authority_id(),
        GithubServerServiceGeneration::new(1)?,
    );
    let live =
        claim_next_maintenance(database, scenario.authority.tenant(), 2_222_000, 2_223_000).await?;
    assert!(
        live.is_none(),
        "a live handoff must exclude its exact revocation from maintenance"
    );
    assert_issuance_state(database, old_key, "revoke_pending").await?;
    Ok(())
}

async fn release_and_revoke_previous(
    database: &TestDatabase,
    scenario: &LifecycleScenario,
) -> TestResult {
    set_database_test_clock(database, 2_223_000).await?;
    database
        .store()
        .release_github_server_service_handoff(ReleaseGithubServerServiceHandoff::new(
            authority_selector(&scenario.authority),
            scenario.handoff_id,
            scenario.consumer,
            UnixMillis::new(2_223_000),
        )?)
        .await
        .map_err(|error| format!("release exact handoff: {error}"))?;
    let old_key = GithubServerServiceIssuanceKey::new(
        scenario.authority.authority_id(),
        GithubServerServiceGeneration::new(1)?,
    );
    let revoke =
        claim_next_revocation(database, &scenario.authority, old_key, 2_224_000, 2_225_000)
            .await
            .map_err(|error| format!("claim prior-generation revocation: {error}"))?;
    set_database_test_clock(database, 2_224_500).await?;
    let revoked = database
        .store()
        .finish_github_server_service_revocation(FinishGithubServerServiceRevocation::confirmed(
            revoke.claim().clone(),
            UnixMillis::new(2_224_500),
        )?)
        .await
        .map_err(|error| format!("finish prior-generation revocation: {error}"))?;
    assert_eq!(revoked.state(), GithubServerServiceIssuanceState::Revoked);
    Ok(())
}

async fn retire_lifecycle_authority(
    database: &TestDatabase,
    authority: &GithubServerServiceAuthorityIdentity,
) -> TestResult {
    set_database_test_clock(database, 2_230_000).await?;
    let retiring = database
        .store()
        .retire_github_server_service_authority(RetireGithubServerServiceAuthority::new(
            authority_selector(authority),
            UnixMillis::new(2_230_000),
        )?)
        .await
        .map_err(|error| format!("retire authority: {error}"))?;
    assert_eq!(
        retiring.state(),
        GithubServerServiceAuthorityState::Retiring
    );
    let current_key = GithubServerServiceIssuanceKey::new(
        authority.authority_id(),
        GithubServerServiceGeneration::new(2)?,
    );
    let current_revoke =
        claim_next_revocation(database, authority, current_key, 2_231_000, 2_232_000)
            .await
            .map_err(|error| format!("claim current-generation revocation: {error}"))?;
    set_database_test_clock(database, 2_231_500).await?;
    database
        .store()
        .finish_github_server_service_revocation(FinishGithubServerServiceRevocation::confirmed(
            current_revoke.claim().clone(),
            UnixMillis::new(2_231_500),
        )?)
        .await
        .map_err(|error| format!("finish current-generation revocation: {error}"))?;
    let retired = database
        .store()
        .inspect_github_server_service_authority(authority.tenant(), authority.authority_id())
        .await?;
    assert_eq!(retired.state(), GithubServerServiceAuthorityState::Retired);
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn handoff_retry_recovers_by_consumer_and_revalidates_current_time_and_fence() -> TestResult {
    run_with_database(|database| async move {
        let first = seed_fixture(&database, "first", 10).await?;
        let second = seed_fixture(&database, "second", 20).await?;
        let first_claim = claim_check(&database, &first, 2_000, 50_000).await?;
        let second_claim = claim_check(&database, &second, 2_100, 50_000).await?;
        let checks_authority = ensure_authority(
            &database,
            &first,
            GithubServerServiceScope::ChecksWrite,
            Uuid::new_v4(),
            100,
        )
        .await?;
        mint_ready(&database, &checks_authority, 1, 1_000, 20_000, 1_100).await?;
        assert_database_test_clock_survives_connection_replacement(&database, 2_900).await?;

        let exact = check_consumer(&first_claim)?;
        let handoff_id =
            acquire_check_handoff_at_exact_claim_tail(&database, &checks_authority, exact).await?;
        assert_check_handoff_replay(&database, &checks_authority, exact, handoff_id).await?;
        assert_replay_rejects_replaced_check_claim(&database, &first, &checks_authority, exact)
            .await?;

        let stale = GithubServerServiceConsumerClaim::new(
            exact.consumer_id(),
            exact.owner(),
            GithubServerServiceClaimFence::new(exact.fence().get() + 1)?,
            exact.action(),
            exact.revision(),
        );
        assert_handoff_rejected(&database, &checks_authority, stale, 3_000).await?;

        let foreign = check_consumer(&second_claim)?;
        assert_handoff_rejected(&database, &checks_authority, foreign, 3_100).await?;

        Ok(())
    })
    .await
}

async fn acquire_check_handoff_at_exact_claim_tail(
    database: &TestDatabase,
    authority: &GithubServerServiceAuthorityIdentity,
    consumer: GithubServerServiceConsumerClaim,
) -> TestResult<GithubServerServiceHandoffId> {
    set_database_test_clock(database, 3_000).await?;
    let excessive_tail = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            authority_selector(authority),
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
            consumer,
            UnixMillis::new(3_000),
            UnixMillis::new(350_001),
        )?)
        .await
        .expect_err("credential custody must not outlive the exact claim tail");
    assert!(matches!(
        excessive_tail,
        GithubServerServiceStoreError::HandoffRejected
    ));

    let handoff_id = GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?;
    database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            authority_selector(authority),
            handoff_id,
            consumer,
            UnixMillis::new(3_000),
            UnixMillis::new(350_000),
        )?)
        .await?;
    Ok(handoff_id)
}

async fn assert_check_handoff_replay(
    database: &TestDatabase,
    authority: &GithubServerServiceAuthorityIdentity,
    consumer: GithubServerServiceConsumerClaim,
    handoff_id: GithubServerServiceHandoffId,
) -> TestResult {
    set_database_test_clock(database, 3_100).await?;
    let replayed = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            authority_selector(authority),
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
            consumer,
            UnixMillis::new(3_100),
            UnixMillis::new(350_000),
        )?)
        .await?;
    assert_eq!(replayed.handoff_id(), handoff_id);
    assert_eq!(replayed.granted_at(), UnixMillis::new(3_000));
    assert_eq!(replayed.acquired_at(), UnixMillis::new(3_100));
    Ok(())
}

async fn assert_replay_rejects_replaced_check_claim(
    database: &TestDatabase,
    fixture: &Fixture,
    authority: &GithubServerServiceAuthorityIdentity,
    consumer: GithubServerServiceConsumerClaim,
) -> TestResult {
    let _replacement_claim = claim_check(database, fixture, 50_000, 60_000).await?;
    set_database_test_clock(database, 50_000).await?;
    let stale_replay = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            authority_selector(authority),
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
            consumer,
            UnixMillis::new(50_000),
            UnixMillis::new(350_000),
        )?)
        .await
        .expect_err("lost-response replay must revalidate the owning durable claim");
    assert!(matches!(
        stale_replay,
        GithubServerServiceStoreError::HandoffRejected
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn renewed_private_consumer_fence_cannot_predate_renewal() -> TestResult {
    run_with_database(|database| async move {
        let (authority, consumer) = prepare_renewed_private_consumer(&database).await?;

        assert_handoff_rejected(&database, &authority, consumer, 2_099).await?;
        set_database_test_clock(&database, 2_100).await?;
        let excessive_tail = database
            .store()
            .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
                authority_selector(&authority),
                GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
                consumer,
                UnixMillis::new(2_100),
                UnixMillis::new(362_101),
            )?)
            .await
            .expect_err("private custody must not outlive the delivery claim tail");
        assert!(matches!(
            excessive_tail,
            GithubServerServiceStoreError::HandoffRejected
        ));
        set_database_test_clock(&database, 2_100).await?;
        let accepted = database
            .store()
            .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
                authority_selector(&authority),
                GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
                consumer,
                UnixMillis::new(2_100),
                UnixMillis::new(362_100),
            )?)
            .await?;
        assert_eq!(accepted.acquired_at(), UnixMillis::new(2_100));
        let changed_files_consumer = GithubServerServiceConsumerClaim::new(
            consumer.consumer_id(),
            consumer.owner(),
            consumer.fence(),
            GithubServerServiceAction::FetchPrivateRepositoryChangedFiles,
            consumer.revision(),
        );
        set_database_test_clock(&database, 2_200).await?;
        let changed_files = database
            .store()
            .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
                authority_selector(&authority),
                GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
                changed_files_consumer,
                UnixMillis::new(2_200),
                UnixMillis::new(40_000),
            )?)
            .await?;
        assert_ne!(accepted.handoff_id(), changed_files.handoff_id());
        assert_eq!(
            changed_files.consumer().action(),
            GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
        );
        Ok(())
    })
    .await
}

async fn prepare_renewed_private_consumer(
    database: &TestDatabase,
) -> TestResult<(
    GithubServerServiceAuthorityIdentity,
    GithubServerServiceConsumerClaim,
)> {
    let fixture = seed_fixture_with_visibility(
        database,
        "private-renewal-observation",
        10,
        ProviderRepositoryVisibility::Private,
    )
    .await?;
    let authority = ensure_authority(
        database,
        &fixture,
        GithubServerServiceScope::PrivateRepositorySourceRead,
        Uuid::new_v4(),
        100,
    )
    .await?;
    mint_ready(database, &authority, 1, 1_000, 20_000, 1_100).await?;

    let monotonic_claimed_at = tokio::time::Instant::now();
    set_database_test_clock(database, 2_000).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(2_000),
            UnixMillis::new(62_000),
        )?)
        .await?
        .expect("private delivery must be claimable");
    let predecessor_confirmed_at = monotonic_claimed_at
        .checked_add(std::time::Duration::from_mins(1))
        .expect("predecessor deadline");
    let monotonic_observed_at = tokio::time::Instant::now();
    let renewal_timing = ProviderDeliveryRenewalTiming::new(
        predecessor_confirmed_at,
        monotonic_observed_at,
        UnixMillis::new(2_100),
        claimed.expires_at(),
    )?;
    set_database_test_clock(database, 2_100).await?;
    let renewed = database
        .store()
        .renew_provider_delivery_claim(RenewProviderDeliveryClaim::new(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            renewal_timing,
            UnixMillis::new(62_100),
        )?)
        .await?;
    assert_eq!(renewed.claimed_at(), UnixMillis::new(2_000));
    assert_eq!(renewed.renewed_at(), UnixMillis::new(2_100));
    let consumer = GithubServerServiceConsumerClaim::new(
        GithubServerServiceConsumerId::from_uuid(renewed.claim().delivery_id().as_uuid())?,
        GithubServerServiceWorkerId::from_uuid(renewed.claim().owner().as_uuid())?,
        GithubServerServiceClaimFence::new(renewed.claim().fence())?,
        GithubServerServiceAction::FetchPrivateRepositoryRevision,
        GithubServerServiceRevision::new(u64::from(renewed.attempt()))?,
    );
    Ok((authority, consumer))
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn expired_post_cutoff_mint_is_indeterminate_and_never_reminted() -> TestResult {
    run_with_database(|database| async move {
        let (identity, claimed) = prepare_expired_mint(&database).await?;

        reject_wrong_mint_window(&database, &identity, &claimed).await?;

        let key = reconcile_expired_mint(&database, &identity, &claimed).await?;

        let next_generation = assert_indeterminate_mint_gate(&database, &identity, key).await?;

        erase_and_advance_indeterminate_mint(&database, &identity, key, next_generation).await?;
        Ok(())
    })
    .await
}

async fn prepare_expired_mint(
    database: &TestDatabase,
) -> TestResult<(
    GithubServerServiceAuthorityIdentity,
    automata_ci_store::ClaimedGithubServerServiceMint,
)> {
    let fixture = seed_fixture(database, "expired-mint", 10).await?;
    let identity = ensure_authority(
        database,
        &fixture,
        GithubServerServiceScope::ChecksWrite,
        Uuid::new_v4(),
        100,
    )
    .await?;
    let claimed = claim_next_mint(
        database,
        &identity,
        GithubServerServiceGeneration::new(1)?,
        1_000,
        2_000,
    )
    .await?;
    set_database_test_clock(database, 1_100).await?;
    database
        .store()
        .begin_github_server_service_mint(BeginGithubServerServiceMint::new(
            &claimed,
            UnixMillis::new(1_100),
        )?)
        .await?;
    Ok((identity, claimed))
}

async fn reject_wrong_mint_window(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    claimed: &automata_ci_store::ClaimedGithubServerServiceMint,
) -> TestResult {
    let wrong_metadata = GithubServerServiceEnvelopeMetadata::new(
        identity.clone(),
        claimed.claim().key().generation(),
        UnixMillis::new(1_001),
        UnixMillis::new(2_001),
        UnixMillis::new(3_601_000),
        32,
        Sha256Digest::from_bytes([21; 32]),
    )?;
    let wrong_envelope = EncryptedEnvelope::from_parts(
        1,
        WrappedDataKey::new(KeyId::new("key-a")?, vec![7; 48])?,
        [8; 12],
        vec![9; 48],
    )?;
    let wrong_window = FinishGithubServerServiceMint::ready(
        claimed.claim().clone(),
        ProtectedGithubServerServiceCredential::new(wrong_metadata, wrong_envelope)?,
        UnixMillis::new(1_200),
    )?;
    set_database_test_clock(database, 1_200).await?;
    let error = database
        .store()
        .finish_github_server_service_mint(&wrong_window)
        .await
        .expect_err("protected AAD must bind the durable request window");
    assert!(matches!(
        error,
        GithubServerServiceStoreError::ClaimRejected
    ));
    Ok(())
}

async fn reconcile_expired_mint(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    claimed: &automata_ci_store::ClaimedGithubServerServiceMint,
) -> TestResult<GithubServerServiceIssuanceKey> {
    let key = claimed.claim().key();
    let early = claim_next_maintenance(database, identity.tenant(), 1_999, 2_099).await?;
    assert!(early.is_none(), "a live mint claim must not be reduced");
    assert_issuance_state(database, key, "minting").await?;

    claim_next_reduced(
        database,
        identity,
        key,
        2_000,
        2_100,
        GithubServerServiceIssuanceState::Indeterminate,
    )
    .await?;
    let replay = claim_next_maintenance(database, identity.tenant(), 2_100, 2_200).await?;
    assert!(
        replay.is_none(),
        "an already reduced generation must not be rediscovered"
    );
    assert_issuance_state(database, key, "indeterminate").await?;
    Ok(key)
}

async fn assert_indeterminate_mint_gate(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    key: GithubServerServiceIssuanceKey,
) -> TestResult<GithubServerServiceGeneration> {
    let remint = claim_next_maintenance(database, identity.tenant(), 2_200, 2_300).await?;
    assert!(
        remint.is_none(),
        "an ambiguous generation must never be reminted"
    );
    assert_issuance_state(database, key, "indeterminate").await?;
    let descriptor = database
        .store()
        .inspect_github_server_service_authority(identity.tenant(), identity.authority_id())
        .await?;
    assert_eq!(descriptor.refresh_generation(), None);

    let next_generation = GithubServerServiceGeneration::new(2)?;
    let gated = claim_next_maintenance(database, identity.tenant(), 2_300, 2_400).await?;
    assert!(
        gated.is_none(),
        "indeterminate authority must gate a successor until safe erasure"
    );
    Ok(next_generation)
}

async fn erase_and_advance_indeterminate_mint(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    key: GithubServerServiceIssuanceKey,
    next_generation: GithubServerServiceGeneration,
) -> TestResult {
    let early = claim_next_maintenance(database, identity.tenant(), 3_781_999, 3_782_099).await?;
    assert!(
        early.is_none(),
        "ambiguous custody must remain until conservative expiry"
    );
    assert_issuance_state(database, key, "indeterminate").await?;
    let claimed =
        claim_next_mint(database, identity, next_generation, 3_782_000, 3_782_500).await?;
    let pre_io_key = GithubServerServiceIssuanceKey::new(identity.authority_id(), next_generation);
    assert_eq!(claimed.claim().key(), pre_io_key);
    assert_issuance_state(database, key, "indeterminate").await?;
    claim_next_reduced(
        database,
        identity,
        key,
        3_782_000,
        3_782_100,
        GithubServerServiceIssuanceState::Revoked,
    )
    .await?;
    claim_next_reduced(
        database,
        identity,
        pre_io_key,
        3_782_500,
        3_782_600,
        GithubServerServiceIssuanceState::Rejected,
    )
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn late_known_token_narrows_indeterminate_failure_gate_to_authenticated_expiry() -> TestResult
{
    run_with_database(|database| async move {
        let fixture = seed_fixture(&database, "late-known-token", 10).await?;
        let identity = ensure_authority(
            &database,
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            Uuid::new_v4(),
            100,
        )
        .await?;
        let generation = GithubServerServiceGeneration::new(1)?;
        let claimed = claim_next_mint(&database, &identity, generation, 1_000, 2_000).await?;
        set_database_test_clock(&database, 1_100).await?;
        database
            .store()
            .begin_github_server_service_mint(BeginGithubServerServiceMint::new(
                &claimed,
                UnixMillis::new(1_100),
            )?)
            .await?;
        let key = claimed.claim().key();
        claim_next_reduced(
            &database,
            &identity,
            key,
            2_000,
            2_100,
            GithubServerServiceIssuanceState::Indeterminate,
        )
        .await?;
        let ambiguous = database
            .store()
            .inspect_github_server_service_authority(identity.tenant(), identity.authority_id())
            .await?;
        assert_eq!(
            ambiguous.next_mint_not_before(),
            Some(UnixMillis::new(3_782_000))
        );

        finish_late_known_token(&database, &identity, &claimed).await?;
        let narrowed = database
            .store()
            .inspect_github_server_service_authority(identity.tenant(), identity.authority_id())
            .await?;
        assert_eq!(
            narrowed.next_mint_not_before(),
            Some(UnixMillis::new(220_000))
        );

        let successor = GithubServerServiceGeneration::new(2)?;
        let early = claim_next_maintenance(&database, identity.tenant(), 219_999, 220_099).await?;
        assert!(
            early.is_none(),
            "the authenticated expiry gate is exclusive"
        );
        claim_next_mint(&database, &identity, successor, 220_000, 220_100).await?;
        Ok(())
    })
    .await
}

async fn finish_late_known_token(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    claimed: &automata_ci_store::ClaimedGithubServerServiceMint,
) -> TestResult {
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        identity.clone(),
        claimed.claim().key().generation(),
        UnixMillis::new(1_000),
        UnixMillis::new(2_000),
        UnixMillis::new(100_000),
        32,
        Sha256Digest::from_bytes([44; 32]),
    )?;
    let protected = ProtectedGithubServerServiceCredential::new(
        metadata,
        EncryptedEnvelope::from_parts(
            1,
            WrappedDataKey::new(KeyId::new("late-key")?, vec![7; 48])?,
            [8; 12],
            vec![9; 48],
        )?,
    )?;
    let revoke_only = FinishGithubServerServiceMint::issued_revoke_only(
        claimed.claim().clone(),
        protected,
        UnixMillis::new(2_100),
    )?;
    set_database_test_clock(database, 2_100).await?;
    let retained = database
        .store()
        .finish_github_server_service_mint(&revoke_only)
        .await?;
    assert_eq!(
        retained.state(),
        GithubServerServiceIssuanceState::RevokePending
    );
    assert_eq!(retained.safe_erase_after(), UnixMillis::new(220_000));
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn authority_creation_is_exact_replay_and_unique_conflicts_are_closed() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_fixture(&database, "authority-replay", 10).await?;
        let authority_uuid = Uuid::new_v4();
        let identity = authority_identity(
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            authority_uuid,
            12,
        )?;
        let request =
            EnsureGithubServerServiceAuthority::new(identity.clone(), UnixMillis::new(100))?;
        let first = database
            .store()
            .ensure_github_server_service_authority(request.clone())
            .await?;
        let replay = database
            .store()
            .ensure_github_server_service_authority(request)
            .await?;
        assert_eq!(replay, first);

        let same_configuration_new_id = authority_identity(
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            Uuid::new_v4(),
            12,
        )?;
        let unique_conflict = database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                same_configuration_new_id,
                UnixMillis::new(100),
            )?)
            .await
            .expect_err("one exact configuration must have one durable authority ID");
        assert!(matches!(
            unique_conflict,
            GithubServerServiceStoreError::IdentityConflict
        ));

        let changed_identity = authority_identity(
            &fixture,
            GithubServerServiceScope::ChecksWrite,
            authority_uuid,
            13,
        )?;
        let identity_conflict = database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                changed_identity,
                UnixMillis::new(100),
            )?)
            .await
            .expect_err("an authority ID must never change immutable configuration");
        assert!(matches!(
            identity_conflict,
            GithubServerServiceStoreError::IdentityConflict
        ));
        Ok(())
    })
    .await
}

async fn assert_handoff_rejected(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: i64,
) -> TestResult {
    set_database_test_clock(database, observed_at).await?;
    let error = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            authority_selector(identity),
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
            consumer,
            UnixMillis::new(observed_at),
            UnixMillis::new(40_000),
        )?)
        .await
        .expect_err("foreign or stale consumer evidence must fail closed");
    assert!(
        matches!(error, GithubServerServiceStoreError::HandoffRejected),
        "unexpected handoff error: {error:?}"
    );
    Ok(())
}

struct Fixture {
    tenant: TenantScope,
    repository_id: RepositoryId,
    connection_id: ProviderConnectionId,
}

async fn seed_fixture(
    database: &TestDatabase,
    suffix: &str,
    accepted_at: i64,
) -> TestResult<Fixture> {
    seed_fixture_with_visibility(
        database,
        suffix,
        accepted_at,
        ProviderRepositoryVisibility::Public,
    )
    .await
}

async fn seed_fixture_with_visibility(
    database: &TestDatabase,
    suffix: &str,
    accepted_at: i64,
    visibility: ProviderRepositoryVisibility,
) -> TestResult<Fixture> {
    install_database_test_clock(database, accepted_at).await?;
    let tenant_text = format!("service-authority-{suffix}-{}", Uuid::new_v4().simple());
    let tenant = TenantScope::from_authenticated_tenant_id(tenant_text.clone())?;
    let connection_id = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
    let manifest = signed_evidence_manifest(tenant.clone(), connection_id, visibility)?;
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                UnixMillis::new(accepted_at),
            ),
        )
        .await?;
    let fixture = Fixture {
        tenant,
        repository_id: manifest.repository_id(),
        connection_id,
    };
    seed_signed_check_delivery(database, &fixture, &manifest, suffix, accepted_at).await?;
    Ok(fixture)
}

fn signed_evidence_manifest(
    tenant: TenantScope,
    connection_id: ProviderConnectionId,
    visibility: ProviderRepositoryVisibility,
) -> TestResult<GithubProviderManifest> {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    Ok(GithubProviderManifest::new(
        tenant,
        connection_id,
        ProviderInstallationId::new(INSTALLATION_ID)?,
        ProviderRepositoryId::new(GITHUB_REPOSITORY_ID)?,
        GithubRepositoryName::new("automata-ci/automata")?,
        visibility,
        GithubServerServiceAppId::new(APP_ID)?,
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766")?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([11; 32]),
        GithubServerServiceRevision::new(EVIDENCE_APP_CONFIGURATION_REVISION)?,
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([7; 32]))?,
        GithubServerServiceRevision::new(1)?,
        GithubServerServiceRevision::new(1)?,
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI")?,
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1)?,
    ))
}

async fn seed_signed_check_delivery(
    database: &TestDatabase,
    fixture: &Fixture,
    manifest: &GithubProviderManifest,
    suffix: &str,
    accepted_at: i64,
) -> TestResult {
    let checks_authority = ensure_evidence_authority(
        database,
        fixture,
        GithubServerServiceScope::ChecksWrite,
        250,
        accepted_at,
    )
    .await?;
    let private_source_authority =
        if manifest.repository_visibility() == ProviderRepositoryVisibility::Private {
            Some(
                ensure_evidence_authority(
                    database,
                    fixture,
                    GithubServerServiceScope::PrivateRepositorySourceRead,
                    251,
                    accepted_at,
                )
                .await?,
            )
        } else {
            None
        };
    let identity = ProviderDeliveryIdentity::new(
        fixture.tenant.clone(),
        "github",
        fixture.connection_id,
        ProviderInstallationId::new(INSTALLATION_ID)?,
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(GITHUB_REPOSITORY_ID)?,
            manifest.repository_visibility(),
            "automata-ci/automata",
        )?,
        format!("delivery-{suffix}"),
    )?;
    let raw_event = AdmissionObject::new(
        Sha256Digest::from_bytes([3; 32]),
        ObjectKey::new(format!("service-authority/{suffix}/event"))?,
        128,
        "application/vnd.automata.github-authenticated-event+json",
    )?;
    let owner = ProviderRepositoryOwnerId::new(EVIDENCE_OWNER_ID)?;
    database
        .store()
        .accept_manifest_pinned_github_delivery(AcceptManifestPinnedGithubDelivery::new(
            AcceptProviderDelivery::new(
                identity,
                Sha256Digest::from_bytes([4; 32]),
                raw_event,
                crate::support::provider_delivery_event_envelope(0x8f),
                UnixMillis::new(accepted_at),
            )?,
            owner,
            owner,
            automata_ci_store::GithubAuthenticatedEvent::new(
                automata_ci_store::GithubAuthenticatedEventKind::Push,
                "refs/heads/main",
            )?,
            GithubCheckHeadSha::new([9; 20])?,
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
        )?)
        .await?;
    retire_evidence_authority(database, &checks_authority, accepted_at + 1).await?;
    if let Some(private_source_authority) = private_source_authority.as_ref() {
        retire_evidence_authority(database, private_source_authority, accepted_at + 1).await?;
    }
    Ok(())
}

async fn ensure_evidence_authority(
    database: &TestDatabase,
    fixture: &Fixture,
    scope: GithubServerServiceScope,
    configuration_byte: u8,
    created_at: i64,
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    let identity = authority_identity_with_app_configuration_revision(
        fixture,
        scope,
        Uuid::new_v4(),
        EVIDENCE_APP_CONFIGURATION_REVISION,
        configuration_byte,
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            identity.clone(),
            UnixMillis::new(created_at),
        )?)
        .await?;
    Ok(identity)
}

async fn retire_evidence_authority(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    observed_at: i64,
) -> TestResult {
    set_database_test_clock(database, observed_at).await?;
    let retired = database
        .store()
        .retire_github_server_service_authority(RetireGithubServerServiceAuthority::new(
            authority_selector(identity),
            UnixMillis::new(observed_at),
        )?)
        .await?;
    assert_eq!(retired.state(), GithubServerServiceAuthorityState::Retired);
    Ok(())
}

async fn claim_check(
    database: &TestDatabase,
    fixture: &Fixture,
    observed_at: i64,
    expires_at: i64,
) -> TestResult<automata_ci_store::ClaimedGithubCheckProjection> {
    set_database_test_clock(database, observed_at).await?;
    database
        .store()
        .claim_github_check_projection(ClaimGithubCheckProjection::new(
            fixture.connection_id,
            GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(observed_at),
            UnixMillis::new(expires_at),
        )?)
        .await?
        .ok_or_else(|| "expected Check projection claim".into())
}

async fn ensure_authority(
    database: &TestDatabase,
    fixture: &Fixture,
    scope: GithubServerServiceScope,
    id: Uuid,
    created_at: i64,
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    ensure_authority_with_app_configuration_revision(
        database, fixture, scope, id, created_at, 1, 12,
    )
    .await
}

async fn ensure_authority_with_app_configuration_revision(
    database: &TestDatabase,
    fixture: &Fixture,
    scope: GithubServerServiceScope,
    id: Uuid,
    created_at: i64,
    app_configuration_revision: u64,
    configuration_byte: u8,
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    set_database_test_clock(database, created_at).await?;
    let identity = authority_identity_with_app_configuration_revision(
        fixture,
        scope,
        id,
        app_configuration_revision,
        configuration_byte,
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            identity.clone(),
            UnixMillis::new(created_at),
        )?)
        .await?;
    Ok(identity)
}

fn authority_identity(
    fixture: &Fixture,
    scope: GithubServerServiceScope,
    id: Uuid,
    configuration_byte: u8,
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    authority_identity_with_app_configuration_revision(fixture, scope, id, 1, configuration_byte)
}

fn authority_identity_with_app_configuration_revision(
    fixture: &Fixture,
    scope: GithubServerServiceScope,
    id: Uuid,
    app_configuration_revision: u64,
    configuration_byte: u8,
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    Ok(GithubServerServiceAuthorityIdentity::new(
        fixture.tenant.clone(),
        GithubServerServiceAuthorityId::from_uuid(id)?,
        fixture.repository_id,
        fixture.connection_id,
        ProviderInstallationId::new(INSTALLATION_ID)?,
        GithubServerServiceAppId::new(APP_ID)?,
        ProviderRepositoryId::new(GITHUB_REPOSITORY_ID)?,
        GithubRepositoryName::new("automata-ci/automata")?,
        scope,
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766")?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([11; 32]),
        GithubServerServiceRevision::new(app_configuration_revision)?,
        GithubServerServiceRevision::new(1)?,
        Sha256Digest::from_bytes([configuration_byte; 32]),
    )?)
}

fn revision_overlap_identity(
    fixture: &Fixture,
    id: Uuid,
    app_configuration_revision: u64,
    policy_revision: u64,
    configuration_byte: u8,
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    Ok(GithubServerServiceAuthorityIdentity::new(
        fixture.tenant.clone(),
        GithubServerServiceAuthorityId::from_uuid(id)?,
        fixture.repository_id,
        fixture.connection_id,
        ProviderInstallationId::new(INSTALLATION_ID)?,
        GithubServerServiceAppId::new(APP_ID)?,
        ProviderRepositoryId::new(GITHUB_REPOSITORY_ID)?,
        GithubRepositoryName::new("automata-ci/automata")?,
        GithubServerServiceScope::ChecksWrite,
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766")?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([11; 32]),
        GithubServerServiceRevision::new(app_configuration_revision)?,
        GithubServerServiceRevision::new(policy_revision)?,
        Sha256Digest::from_bytes([configuration_byte; 32]),
    )?)
}

async fn assert_revision_overlap_catalog(database: &TestDatabase) -> TestResult {
    let obsolete_index_count: i64 = sqlx::query_scalar(
        r"
        SELECT count(*)
        FROM pg_catalog.pg_class AS catalog_relation
        JOIN pg_catalog.pg_namespace AS catalog_namespace
          ON catalog_namespace.oid = catalog_relation.relnamespace
        WHERE catalog_namespace.nspname = current_schema()
          AND catalog_relation.relname =
              'github_server_service_authorities_one_active_scope'
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        obsolete_index_count, 0,
        "obsolete active-scope index remains"
    );

    let constraints: Vec<(String, Vec<String>)> = sqlx::query_as(
        r"
        SELECT catalog_constraint.conname,
               array_agg(catalog_attribute.attname::TEXT
                         ORDER BY constraint_key.ordinality)
        FROM pg_catalog.pg_constraint AS catalog_constraint
        JOIN pg_catalog.pg_class AS catalog_relation
          ON catalog_relation.oid = catalog_constraint.conrelid
        JOIN pg_catalog.pg_namespace AS catalog_namespace
          ON catalog_namespace.oid = catalog_relation.relnamespace
        CROSS JOIN LATERAL
          pg_catalog.unnest(catalog_constraint.conkey)
          WITH ORDINALITY AS constraint_key(attnum, ordinality)
        JOIN pg_catalog.pg_attribute AS catalog_attribute
          ON catalog_attribute.attrelid = catalog_constraint.conrelid
         AND catalog_attribute.attnum = constraint_key.attnum
        WHERE catalog_namespace.nspname = current_schema()
          AND catalog_relation.relname = 'github_server_service_authorities'
          AND catalog_constraint.contype = 'u'
          AND catalog_constraint.conname IN (
              'github_server_service_authorities_exact_config_unique',
              'github_server_service_authorities_repository_scope_revision_uni'
          )
        GROUP BY catalog_constraint.conname
        ORDER BY catalog_constraint.conname
        ",
    )
    .fetch_all(database.pool())
    .await?;
    assert_eq!(
        constraints,
        vec![
            (
                "github_server_service_authorities_exact_config_unique".into(),
                vec![
                    "tenant_id".into(),
                    "repository_id".into(),
                    "provider_connection_id".into(),
                    "provider_installation_id".into(),
                    "service_scope".into(),
                    "app_configuration_revision".into(),
                    "policy_revision".into(),
                    "configuration_fingerprint".into(),
                ],
            ),
            (
                "github_server_service_authorities_repository_scope_revision_uni".into(),
                vec![
                    "tenant_id".into(),
                    "repository_id".into(),
                    "service_scope".into(),
                    "app_configuration_revision".into(),
                    "policy_revision".into(),
                ],
            ),
        ]
    );
    Ok(())
}

async fn assert_revision_lock_isolation(
    database: &TestDatabase,
    revision_7: &GithubServerServiceAuthorityIdentity,
    revision_8: &GithubServerServiceAuthorityIdentity,
) -> TestResult {
    let mut blocker = database.pool().begin().await?;
    let locked_revision_7: Uuid = sqlx::query_scalar(
        "SELECT id FROM github_server_service_authorities WHERE id = $1 FOR UPDATE",
    )
    .bind(revision_7.authority_id().as_uuid())
    .fetch_one(&mut *blocker)
    .await?;
    assert_eq!(locked_revision_7, revision_7.authority_id().as_uuid());

    let mut contender = database.pool().begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '250ms'")
        .execute(&mut *contender)
        .await?;
    let locked_revision_8 = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM github_server_service_authorities WHERE id = $1 FOR UPDATE NOWAIT",
        )
        .bind(revision_8.authority_id().as_uuid())
        .fetch_one(&mut *contender),
    )
    .await??;
    assert_eq!(locked_revision_8, revision_8.authority_id().as_uuid());

    let blocked_revision_7 = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM github_server_service_authorities WHERE id = $1 FOR UPDATE NOWAIT",
    )
    .bind(revision_7.authority_id().as_uuid())
    .fetch_one(&mut *contender)
    .await
    .expect_err("revision 7 row lock must still be held");
    let database_error = blocked_revision_7
        .as_database_error()
        .expect("database lock error");
    assert_eq!(database_error.code().as_deref(), Some("55P03"));
    contender.rollback().await?;
    blocker.rollback().await?;
    Ok(())
}

async fn insert_authority_direct(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    created_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
        INSERT INTO github_server_service_authorities (
            id, tenant_id, repository_id, provider_connection_id,
            provider_installation_id, github_app_id, github_app_client_id,
            github_app_jwt_issuer_kind, github_repository_id,
            github_repository_name, service_scope, permission_policy,
            policy_digest, policy_revision, app_key_spki_sha256,
            app_configuration_revision, configuration_fingerprint,
            identity_digest, state, created_at_ms, state_updated_at_ms
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12::JSONB, $13, $14, $15, $16, $17, $18,
            'active', $19, $19
        )
        ",
    )
    .bind(identity.authority_id().as_uuid())
    .bind(identity.tenant().as_str())
    .bind(identity.repository_id().as_uuid())
    .bind(identity.connection_id().as_uuid())
    .bind(i64::try_from(identity.installation_id().get()).expect("installation fits i64"))
    .bind(i64::try_from(identity.github_app_id().get()).expect("App ID fits i64"))
    .bind(identity.app_client_id().as_str())
    .bind(identity.jwt_issuer().as_str())
    .bind(i64::try_from(identity.github_repository_id().get()).expect("repository fits i64"))
    .bind(identity.github_repository_name().as_str())
    .bind(identity.scope().as_str())
    .bind(identity.scope().permissions_json())
    .bind(identity.policy_digest().as_bytes().as_slice())
    .bind(i64::try_from(identity.policy_revision().get()).expect("policy revision fits i64"))
    .bind(identity.app_key_spki_sha256().as_bytes().as_slice())
    .bind(
        i64::try_from(identity.app_configuration_revision().get())
            .expect("App configuration revision fits i64"),
    )
    .bind(identity.configuration_fingerprint().as_bytes().as_slice())
    .bind(identity.identity_digest().as_bytes().as_slice())
    .bind(created_at)
    .execute(database.pool())
    .await?;
    Ok(())
}

fn assert_unique_constraint(error: &sqlx::Error, expected: &str) {
    let database = error.as_database_error().expect("database error");
    assert_eq!(database.code().as_deref(), Some("23505"));
    assert_eq!(database.constraint(), Some(expected));
}

fn authority_selector(
    identity: &GithubServerServiceAuthorityIdentity,
) -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_identity(identity)
}

async fn claim_next_maintenance(
    database: &TestDatabase,
    tenant: &TenantScope,
    observed_at: i64,
    expires_at: i64,
) -> TestResult<Option<GithubServerServiceMaintenanceOutcome>> {
    set_database_test_clock(database, observed_at).await?;
    Ok(database
        .store()
        .claim_next_github_server_service_maintenance(ClaimNextGithubServerServiceMaintenance::new(
            tenant.clone(),
            GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(observed_at),
            UnixMillis::new(expires_at),
        )?)
        .await?)
}

async fn claim_next_mint(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    generation: GithubServerServiceGeneration,
    observed_at: i64,
    expires_at: i64,
) -> TestResult<automata_ci_store::ClaimedGithubServerServiceMint> {
    let outcome = claim_next_maintenance(database, identity.tenant(), observed_at, expires_at)
        .await?
        .expect("the exact authority must have one due mint");
    let GithubServerServiceMaintenanceOutcome::Mint(claimed) = outcome else {
        panic!("the exact authority must produce a mint outcome");
    };
    let expected_key = GithubServerServiceIssuanceKey::new(identity.authority_id(), generation);
    assert_eq!(claimed.claim().selector(), &authority_selector(identity));
    assert_eq!(claimed.claim().key(), expected_key);
    Ok(*claimed)
}

async fn claim_next_revocation(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    key: GithubServerServiceIssuanceKey,
    observed_at: i64,
    expires_at: i64,
) -> TestResult<automata_ci_store::ClaimedGithubServerServiceRevocation> {
    let outcome = claim_next_maintenance(database, identity.tenant(), observed_at, expires_at)
        .await?
        .expect("the exact authority must have one due revocation");
    let GithubServerServiceMaintenanceOutcome::Revocation(claimed) = outcome else {
        panic!("the exact authority must produce a revocation outcome");
    };
    assert_eq!(claimed.claim().selector(), &authority_selector(identity));
    assert_eq!(claimed.claim().key(), key);
    Ok(*claimed)
}

async fn claim_next_reduced(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    key: GithubServerServiceIssuanceKey,
    observed_at: i64,
    expires_at: i64,
    expected_state: GithubServerServiceIssuanceState,
) -> TestResult<automata_ci_store::GithubServerServiceIssuanceReceipt> {
    let outcome = claim_next_maintenance(database, identity.tenant(), observed_at, expires_at)
        .await?
        .expect("the exact authority must have one due reduction");
    let GithubServerServiceMaintenanceOutcome::Reduced { selector, receipt } = outcome else {
        panic!("the exact authority must produce a reduced outcome");
    };
    assert_eq!(selector, authority_selector(identity));
    assert_eq!(receipt.key(), key);
    assert_eq!(receipt.state(), expected_state);
    Ok(receipt)
}

async fn assert_issuance_state(
    database: &TestDatabase,
    key: GithubServerServiceIssuanceKey,
    expected: &str,
) -> TestResult {
    let state: String = sqlx::query_scalar(
        r"
        SELECT state
        FROM github_server_service_authority_issuances
        WHERE authority_id = $1 AND generation = $2
        ",
    )
    .bind(key.authority_id().as_uuid())
    .bind(i64::try_from(key.generation().get())?)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(state, expected);
    Ok(())
}

async fn mint_ready(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    generation: u64,
    requested_at: i64,
    claim_expires_at: i64,
    committed_at: i64,
) -> TestResult {
    let generation_number = generation;
    let generation = GithubServerServiceGeneration::new(generation)?;
    let claimed = claim_next_mint(
        database,
        identity,
        generation,
        requested_at,
        claim_expires_at,
    )
    .await
    .map_err(|error| format!("claim ready generation {generation_number}: {error}"))?;
    set_database_test_clock(database, requested_at + 10).await?;
    database
        .store()
        .begin_github_server_service_mint(BeginGithubServerServiceMint::new(
            &claimed,
            UnixMillis::new(requested_at + 10),
        )?)
        .await
        .map_err(|error| format!("begin ready generation {generation_number}: {error}"))?;
    let provider_expires_at = UnixMillis::new(requested_at + 3_600_000);
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        identity.clone(),
        generation,
        UnixMillis::new(requested_at),
        UnixMillis::new(claim_expires_at),
        provider_expires_at,
        32,
        Sha256Digest::from_bytes([21; 32]),
    )?;
    let envelope = EncryptedEnvelope::from_parts(
        1,
        WrappedDataKey::new(KeyId::new("key-a")?, vec![7; 48])?,
        [8; 12],
        vec![9; 48],
    )?;
    let protected = ProtectedGithubServerServiceCredential::new(metadata, envelope)?;
    let ready = FinishGithubServerServiceMint::ready(
        claimed.claim().clone(),
        protected,
        UnixMillis::new(committed_at),
    )?;
    set_database_test_clock(database, committed_at).await?;
    let receipt = database
        .store()
        .finish_github_server_service_mint(&ready)
        .await
        .map_err(|error| format!("finish ready generation {generation:?}: {error}"))?;
    assert_eq!(receipt.state(), GithubServerServiceIssuanceState::Ready);
    Ok(())
}

fn check_consumer(
    claimed: &automata_ci_store::ClaimedGithubCheckProjection,
) -> TestResult<GithubServerServiceConsumerClaim> {
    let action = match claimed.action() {
        GithubCheckProjectionAction::EnsureSuite => GithubServerServiceAction::EnsureCheckSuite,
        GithubCheckProjectionAction::PrepareRunCreate => GithubServerServiceAction::CreateCheckRun,
        GithubCheckProjectionAction::ReconcileRunCreate => {
            GithubServerServiceAction::ReconcileCheckRun
        }
        GithubCheckProjectionAction::Publish => GithubServerServiceAction::PublishCheckRun,
    };
    Ok(GithubServerServiceConsumerClaim::new(
        GithubServerServiceConsumerId::from_uuid(claimed.claim().subject_id().as_uuid())?,
        GithubServerServiceWorkerId::from_uuid(claimed.claim().owner().as_uuid())?,
        GithubServerServiceClaimFence::new(claimed.claim().fence())?,
        action,
        GithubServerServiceRevision::new(claimed.desired_revision())?,
    ))
}
