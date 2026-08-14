use std::{sync::Arc, time::Duration};

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_key_management::{EncryptedEnvelope, KeyId, WrappedDataKey};
use automata_ci_store::{
    BeginGithubServerServiceMint, BeginGithubServerServiceMintOutcome,
    ClaimGithubServerServiceMint, ClaimGithubServerServiceRevocation,
    ClaimNextGithubServerServiceMaintenance, EnsureGithubServerServiceAuthority,
    EraseExpiredGithubServerServiceIssuance, FinishGithubServerServiceMint, GithubRepositoryName,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository as _,
    GithubServerServiceAuthoritySelector, GithubServerServiceEnvelopeMetadata,
    GithubServerServiceGeneration, GithubServerServiceIssuanceState, GithubServerServiceJwtIssuer,
    GithubServerServiceMaintenanceOutcome, GithubServerServiceRevision, GithubServerServiceScope,
    GithubServerServiceStoreError, GithubServerServiceWorkerId,
    ProtectedGithubServerServiceCredential, ProviderConnectionId, ProviderInstallationId,
    ProviderRepositoryId, ReconcileExpiredGithubServerServiceMint, RepositoryId, TenantScope,
};
use sqlx::{PgPool, migrate::Migrate as _};
use uuid::Uuid;

use crate::support::{TestClock, TestDatabase, TestResult, run_with_unmigrated_database};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const CLAIM_DURATION_MILLIS: i64 = 2_000;
const REQUEST_DURATION_MILLIS: i64 = 10_000;

#[derive(Clone)]
struct Fixture {
    tenant: TenantScope,
    identity: GithubServerServiceAuthorityIdentity,
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn caller_clock_is_admission_only_and_database_issues_full_duration() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_authority_migrations(&database).await?;
        let fixture = seed_authority(&database).await?;
        for skew in [-120_000, 120_000] {
            let observed_at = database_now_ms(&database).await? + skew;
            let result = database
                .store()
                .claim_next_github_server_service_maintenance(
                    ClaimNextGithubServerServiceMaintenance::new(
                        fixture.tenant.clone(),
                        GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                        UnixMillis::new(observed_at),
                        UnixMillis::new(observed_at + CLAIM_DURATION_MILLIS),
                    )?,
                )
                .await;
            assert!(matches!(
                result,
                Err(GithubServerServiceStoreError::ClaimRejected)
            ));
        }
        let issuance_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_server_service_authority_issuances")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(issuance_count, 0, "skew rejection must be side-effect free");

        let caller_observed_at = database_now_ms(&database).await? - 30_000;
        let before_claim = database_now_ms(&database).await?;
        let outcome = database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::new(
                    fixture.tenant,
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    UnixMillis::new(caller_observed_at),
                    UnixMillis::new(caller_observed_at + CLAIM_DURATION_MILLIS),
                )?,
            )
            .await?
            .expect("bootstrap authority must produce a mint claim");
        let GithubServerServiceMaintenanceOutcome::Mint(claimed) = outcome else {
            panic!("bootstrap authority returned non-mint maintenance");
        };
        let after_claim = database_now_ms(&database).await?;
        assert!(claimed.claimed_at().get() >= before_claim);
        assert!(claimed.claimed_at().get() <= after_claim);
        assert_eq!(claimed.receipt().requested_at(), claimed.claimed_at());
        assert_eq!(
            claimed.claim_expires_at().get() - claimed.claimed_at().get(),
            CLAIM_DURATION_MILLIS
        );
        assert_eq!(
            claimed.receipt().request_deadline().get() - claimed.receipt().requested_at().get(),
            CLAIM_DURATION_MILLIS
        );
        assert_ne!(claimed.claimed_at().get(), caller_observed_at);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn delayed_authority_lock_rebases_both_fences_and_replays_exact_duration() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        apply_authority_migrations(&database).await?;
        let fixture = seed_authority(&database).await?;
        let caller_observed_at = database_now_ms(&database).await?;
        let request = ClaimGithubServerServiceMint::new(
            selector(&fixture.identity),
            GithubServerServiceGeneration::new(1)?,
            GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(caller_observed_at),
            UnixMillis::new(caller_observed_at + REQUEST_DURATION_MILLIS),
            UnixMillis::new(caller_observed_at + CLAIM_DURATION_MILLIS),
        )?;
        let replay_request = request.clone();

        let mut blocker = database.pool().begin().await?;
        let blocking_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM github_server_service_authorities WHERE id = $1 FOR UPDATE")
            .bind(fixture.identity.authority_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;

        let claimant_database = Arc::clone(&database);
        let claimant = tokio::spawn(async move {
            claimant_database
                .store()
                .claim_github_server_service_mint(request)
                .await
        });
        wait_for_backend_blocked_by(
            database.pool(),
            blocking_backend_pid,
            "FROM github_server_service_authorities",
        )
        .await?;
        clock
            .set(
                caller_observed_at
                    .checked_add(CLAIM_DURATION_MILLIS + 1)
                    .ok_or("service-authority delayed-claim clock overflow")?,
            )
            .await?;
        let release_floor = database_now_ms(&database).await?;
        blocker.commit().await?;

        let claimed = tokio::time::timeout(Duration::from_secs(10), claimant).await???;
        assert!(claimed.claimed_at().get() >= release_floor);
        assert_eq!(claimed.receipt().requested_at(), claimed.claimed_at());
        assert_eq!(
            claimed.claim_expires_at().get() - claimed.claimed_at().get(),
            CLAIM_DURATION_MILLIS
        );
        assert_eq!(
            claimed.receipt().request_deadline().get() - claimed.receipt().requested_at().get(),
            REQUEST_DURATION_MILLIS
        );
        assert!(
            claimed.claimed_at().get() >= caller_observed_at + CLAIM_DURATION_MILLIS,
            "the original caller lease had elapsed before the row lock was released"
        );

        let replayed = database
            .store()
            .claim_github_server_service_mint(replay_request)
            .await?;
        assert_eq!(
            replayed, claimed,
            "rebased lost response must replay exactly"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn fast_clock_cannot_reduce_live_mint_or_erase_ready_custody() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_authority_migrations(&database).await?;
        let fixture = seed_authority(&database).await?;
        let claimed = claim_and_begin(&database, &fixture, 30_000, 120_000).await?;

        let fast_observed_at = database_now_ms(&database).await? + 45_000;
        let maintenance = database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::new(
                    fixture.tenant.clone(),
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    UnixMillis::new(fast_observed_at),
                    UnixMillis::new(fast_observed_at + 1_000),
                )?,
            )
            .await?;
        assert!(
            maintenance.is_none(),
            "database-live mint must not be reduced"
        );

        let reconcile = database
            .store()
            .reconcile_expired_github_server_service_mint(
                ReconcileExpiredGithubServerServiceMint::new(
                    selector(&fixture.identity),
                    claimed.claim().key(),
                    UnixMillis::new(fast_observed_at),
                )?,
            )
            .await;
        assert!(matches!(
            reconcile,
            Err(GithubServerServiceStoreError::ClaimRejected)
        ));

        let committed_at = UnixMillis::new(database_now_ms(&database).await?);
        let protected = protected_for_claim(&fixture.identity, &claimed)?;
        let finish =
            FinishGithubServerServiceMint::ready(claimed.claim().clone(), protected, committed_at)?;
        let ready = database
            .store()
            .finish_github_server_service_mint(&finish)
            .await?;
        assert_eq!(ready.state(), GithubServerServiceIssuanceState::Ready);

        let erase = database
            .store()
            .erase_expired_github_server_service_issuance(
                EraseExpiredGithubServerServiceIssuance::new(
                    selector(&fixture.identity),
                    ready.key(),
                    ready.safe_erase_after(),
                )?,
            )
            .await;
        assert!(matches!(
            erase,
            Err(GithubServerServiceStoreError::ClaimRejected)
        ));
        let scan = database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::new(
                    fixture.tenant,
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    ready.safe_erase_after(),
                    UnixMillis::new(ready.safe_erase_after().get() + 1_000),
                )?,
            )
            .await;
        assert!(matches!(
            scan,
            Err(GithubServerServiceStoreError::ClaimRejected)
        ));
        assert_protected_state(&database, ready.key(), "ready").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn late_ready_result_is_retained_revoke_only_and_replays() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        apply_authority_migrations(&database).await?;
        let fixture = seed_authority(&database).await?;
        let claimed = claim_and_begin(&database, &fixture, 2_000, 5_000).await?;
        let protected = protected_for_claim(&fixture.identity, &claimed)?;
        let committed_at = UnixMillis::new(claimed.claimed_at().get() + 50);
        let finish =
            FinishGithubServerServiceMint::ready(claimed.claim().clone(), protected, committed_at)?;
        wait_until_database_time(&clock, claimed.claim_expires_at().get()).await?;
        let begin_replay = database
            .store()
            .begin_github_server_service_mint(BeginGithubServerServiceMint::new(
                &claimed,
                claimed.claimed_at(),
            )?)
            .await?;
        assert!(matches!(
            begin_replay,
            BeginGithubServerServiceMintOutcome::AlreadyStarted(_)
        ));

        let retained = database
            .store()
            .finish_github_server_service_mint(&finish)
            .await?;
        assert_eq!(
            retained.state(),
            GithubServerServiceIssuanceState::RevokePending
        );
        assert_protected_state(&database, retained.key(), "revoke_pending").await?;
        let replayed = database
            .store()
            .finish_github_server_service_mint(&finish)
            .await?;
        assert_eq!(replayed, retained);

        let revocation_observed_at = database_now_ms(&database).await?;
        let revocation_request = ClaimGithubServerServiceRevocation::new(
            selector(&fixture.identity),
            retained.key(),
            GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(revocation_observed_at),
            UnixMillis::new(revocation_observed_at + 500),
        )?;
        let revocation_replay_request = revocation_request.clone();
        let first = database
            .store()
            .claim_github_server_service_revocation(revocation_request.clone())
            .await?;
        let replay = database
            .store()
            .claim_github_server_service_revocation(revocation_replay_request)
            .await?;
        assert_eq!(replay.claim(), first.claim());
        assert_eq!(replay.claimed_at(), first.claimed_at());
        assert_eq!(replay.claim_expires_at(), first.claim_expires_at());

        wait_until_database_time(&clock, first.claim_expires_at().get()).await?;
        let takeover = database
            .store()
            .claim_github_server_service_revocation(revocation_request)
            .await?;
        assert_eq!(
            takeover.claim().fence().get(),
            first.claim().fence().get() + 1
        );
        assert!(takeover.claimed_at() >= first.claim_expires_at());
        assert_eq!(
            takeover.claim_expires_at().get() - takeover.claimed_at().get(),
            500
        );
        Ok(())
    })
    .await
}

async fn apply_authority_migrations(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR.iter().filter(|migration| migration.version <= 32) {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

async fn seed_authority(database: &TestDatabase) -> TestResult<Fixture> {
    let now = database_now_ms(database).await?;
    let tenant = TenantScope::from_authenticated_tenant_id(format!(
        "clock-authority-{}",
        Uuid::new_v4().simple()
    ))?;
    let repository_uuid = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Clock authority test', $2, $2)
        ",
    )
    .bind(tenant.as_str())
    .bind(now)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', '202', 'automata-ci', 'automata', $3, $3)
        ",
    )
    .bind(repository_uuid)
    .bind(tenant.as_str())
    .bind(now)
    .execute(database.pool())
    .await?;

    let identity = GithubServerServiceAuthorityIdentity::new(
        tenant.clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::new_v4())?,
        RepositoryId::from_uuid(repository_uuid),
        ProviderConnectionId::from_uuid(Uuid::new_v4())?,
        ProviderInstallationId::new(101)?,
        GithubServerServiceAppId::new(303)?,
        ProviderRepositoryId::new(202)?,
        GithubRepositoryName::new("automata-ci/automata")?,
        GithubServerServiceScope::ChecksWrite,
        GithubServerServiceAppClientId::new("Iv1.clock-authority")?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([11; 32]),
        GithubServerServiceRevision::new(1)?,
        GithubServerServiceRevision::new(1)?,
        Sha256Digest::from_bytes([12; 32]),
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            identity.clone(),
            UnixMillis::new(now),
        )?)
        .await?;
    Ok(Fixture { tenant, identity })
}

async fn claim_and_begin(
    database: &TestDatabase,
    fixture: &Fixture,
    claim_duration: i64,
    request_duration: i64,
) -> TestResult<automata_ci_store::ClaimedGithubServerServiceMint> {
    let observed_at = database_now_ms(database).await?;
    let claimed = database
        .store()
        .claim_github_server_service_mint(ClaimGithubServerServiceMint::new(
            selector(&fixture.identity),
            GithubServerServiceGeneration::new(1)?,
            GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(observed_at),
            UnixMillis::new(observed_at + request_duration),
            UnixMillis::new(observed_at + claim_duration),
        )?)
        .await?;
    database
        .store()
        .begin_github_server_service_mint(BeginGithubServerServiceMint::new(
            &claimed,
            claimed.claimed_at(),
        )?)
        .await?;
    Ok(claimed)
}

fn protected_for_claim(
    identity: &GithubServerServiceAuthorityIdentity,
    claimed: &automata_ci_store::ClaimedGithubServerServiceMint,
) -> TestResult<ProtectedGithubServerServiceCredential> {
    let receipt = claimed.receipt();
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        identity.clone(),
        claimed.claim().key().generation(),
        receipt.requested_at(),
        receipt.request_deadline(),
        UnixMillis::new(receipt.requested_at().get() + 3_600_000),
        32,
        Sha256Digest::from_bytes([21; 32]),
    )?;
    Ok(ProtectedGithubServerServiceCredential::new(
        metadata,
        EncryptedEnvelope::from_parts(
            1,
            WrappedDataKey::new(KeyId::new("clock-test-key")?, vec![7; 48])?,
            [8; 12],
            vec![9; 48],
        )?,
    )?)
}

fn selector(
    identity: &GithubServerServiceAuthorityIdentity,
) -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_identity(identity)
}

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}

async fn wait_until_database_time(clock: &TestClock, target: i64) -> TestResult {
    clock
        .set(
            target
                .checked_add(1)
                .ok_or("service-authority expiry clock overflow")?,
        )
        .await?;
    Ok(())
}

async fn assert_protected_state(
    database: &TestDatabase,
    key: automata_ci_store::GithubServerServiceIssuanceKey,
    expected_state: &str,
) -> TestResult {
    let (state, protected): (String, bool) = sqlx::query_as(
        r"
        SELECT state, ciphertext IS NOT NULL
        FROM github_server_service_authority_issuances
        WHERE authority_id = $1 AND generation = $2
        ",
    )
    .bind(key.authority_id().as_uuid())
    .bind(i64::try_from(key.generation().get())?)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(state, expected_state);
    assert!(protected, "protected custody must remain durable");
    Ok(())
}

async fn wait_for_backend_blocked_by(
    pool: &PgPool,
    blocking_backend_pid: i32,
    query_fragment: &str,
) -> TestResult<i32> {
    for _ in 0..500 {
        let waiting_backend_pid: Option<i32> = sqlx::query_scalar(
            r"
            SELECT pid
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND pid <> $1
              AND $1 = ANY(pg_blocking_pids(pid))
              AND query LIKE '%' || $2 || '%'
            ORDER BY pid
            LIMIT 1
            ",
        )
        .bind(blocking_backend_pid)
        .bind(query_fragment)
        .fetch_optional(pool)
        .await?;
        if let Some(waiting_backend_pid) = waiting_backend_pid {
            return Ok(waiting_backend_pid);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("backend did not block on expected {query_fragment} lock").into())
}
