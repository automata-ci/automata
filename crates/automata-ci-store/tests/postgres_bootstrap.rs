#[allow(dead_code)]
use crate::common;

use std::time::Duration;

use automata_ci_core::{
    Architecture, OperatingSystem, RunnerCapabilities, RunnerFeature, RunnerGroup, RunnerId,
    RunnerLabel, RunnerPlatform, Sha256Digest, UnixMillis,
};
use automata_ci_store::{
    EnsureTenant, MAX_STATIC_RUNNERS, ProductBootstrapRepository as _, ProductBootstrapStoreError,
    RunnerCapabilityReadiness, RunnerSlotCount, StaticRunnerFleet, StaticRunnerRegistration,
    TenantScope,
};

use common::{TestResult, run_with_database};

fn fleet(tenant_name: &str, runner_id: RunnerId) -> StaticRunnerFleet {
    fleet_with_certificates(tenant_name, runner_id, &[(7, 2_000_000_000)], 1_000)
}

fn fleet_with_certificates(
    tenant_name: &str,
    runner_id: RunnerId,
    certificates: &[(u8, i64)],
    applied_at_ms: i64,
) -> StaticRunnerFleet {
    let label = RunnerLabel::new("linux").expect("label");
    let group = RunnerGroup::new("g1").expect("group");
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([label.clone()])
    .with_groups([group.clone()])
    .with_max_parallel_jobs(2)
    .expect("slots");
    let runner = StaticRunnerRegistration::try_new(
        runner_id,
        "runner-a",
        "spiffe://automata/runner-a",
        vec![label],
        capabilities,
        RunnerSlotCount::new(2).expect("slots"),
        certificates
            .iter()
            .map(|(byte, expiry)| (Sha256Digest::from_bytes([*byte; 32]), *expiry))
            .collect(),
    )
    .expect("registration");
    StaticRunnerFleet::try_new(
        TenantScope::from_authenticated_tenant_id(tenant_name).expect("tenant"),
        group,
        vec![runner],
        UnixMillis::new(applied_at_ms),
    )
    .expect("fleet")
}

fn runner_capabilities(
    runner_id: RunnerId,
    features: impl IntoIterator<Item = RunnerFeature>,
) -> RunnerCapabilities {
    RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_labels([RunnerLabel::new("linux").expect("label")])
    .with_groups([RunnerGroup::new("g1").expect("group")])
    .with_max_parallel_jobs(2)
    .expect("slots")
    .with_features(features)
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn tenant_and_static_fleet_bootstrap_are_fresh_database_idempotent() -> TestResult {
    run_with_database(|database| async move {
        let tenant = TenantScope::from_authenticated_tenant_id("fresh-bootstrap")?;
        let ensure = EnsureTenant::new(tenant, UnixMillis::new(500));
        database.store().ensure_tenant(ensure.clone()).await?;
        database.store().ensure_tenant(ensure).await?;

        let runner_id = RunnerId::new();
        let configured = fleet("fresh-bootstrap", runner_id);
        database
            .store()
            .apply_static_runner_fleet(configured.clone())
            .await?;
        database
            .store()
            .apply_static_runner_fleet(configured)
            .await?;

        let row: (String, i32, String, i64) = sqlx::query_as(
            r"
            SELECT runner.external_identity, runner.slots, runner.desired_state,
                   certificate.expires_at_seconds
            FROM runners AS runner
            JOIN runner_machine_certificates AS certificate
              ON certificate.runner_id = runner.id
            WHERE runner.id = $1
            ",
        )
        .bind(runner_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(row.0, "spiffe://automata/runner-a");
        assert_eq!(row.1, 2);
        assert_eq!(row.2, "active");
        assert_eq!(row.3, 2_000_000_000);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn durable_runner_capability_admission_is_canonical_bound_and_oidc_dark() -> TestResult {
    run_with_database(|database| async move {
        let runner_id = RunnerId::new();
        database
            .store()
            .apply_static_runner_fleet(fleet("capability-admission", runner_id))
            .await?;
        database
            .store()
            .verify_runner_capability_admission()
            .await?;

        let non_oidc = runner_capabilities(runner_id, [RunnerFeature::SHELL_STEPS]);
        sqlx::query("UPDATE runners SET capabilities = $2 WHERE id = $1")
            .bind(runner_id.as_uuid())
            .bind(serde_json::to_value(non_oidc)?)
            .execute(database.pool())
            .await?;
        database
            .store()
            .verify_runner_capability_admission()
            .await?;

        let oidc = runner_capabilities(
            runner_id,
            [RunnerFeature::SHELL_STEPS, RunnerFeature::OIDC_TOKENS],
        );
        sqlx::query("UPDATE runners SET capabilities = $2 WHERE id = $1")
            .bind(runner_id.as_uuid())
            .bind(serde_json::to_value(oidc)?)
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database.store().verify_runner_capability_admission().await,
            Err(ProductBootstrapStoreError::ConfigurationDrift {
                resource: "runner capability admission"
            })
        ));
        database
            .store()
            .verify_runner_capability_readiness(
                RunnerCapabilityReadiness::unavailable().with_github_oidc(),
            )
            .await?;

        let mismatched = runner_capabilities(RunnerId::new(), [RunnerFeature::SHELL_STEPS]);
        sqlx::query("UPDATE runners SET capabilities = $2 WHERE id = $1")
            .bind(runner_id.as_uuid())
            .bind(serde_json::to_value(mismatched)?)
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database.store().verify_runner_capability_admission().await,
            Err(ProductBootstrapStoreError::CorruptData)
        ));

        let mut noncanonical =
            serde_json::to_value(runner_capabilities(runner_id, [RunnerFeature::SHELL_STEPS]))?;
        noncanonical["features"] = serde_json::json!([
            RunnerFeature::SHELL_STEPS.as_str(),
            RunnerFeature::SHELL_STEPS.as_str()
        ]);
        sqlx::query("UPDATE runners SET capabilities = $2 WHERE id = $1")
            .bind(runner_id.as_uuid())
            .bind(noncanonical)
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database.store().verify_runner_capability_admission().await,
            Err(ProductBootstrapStoreError::CorruptData)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn durable_runner_capability_admission_has_one_fleet_total_ceiling() -> TestResult {
    run_with_database(|database| async move {
        let first_id = RunnerId::new();
        database
            .store()
            .apply_static_runner_fleet(fleet("capability-ceiling", first_id))
            .await?;
        let group_id: uuid::Uuid = sqlx::query_scalar("SELECT group_id FROM runners WHERE id = $1")
            .bind(first_id.as_uuid())
            .fetch_one(database.pool())
            .await?;

        for index in 1..=MAX_STATIC_RUNNERS {
            let runner_id = RunnerId::new();
            let capabilities = runner_capabilities(runner_id, [RunnerFeature::SHELL_STEPS]);
            let name = format!("overflow-{index}");
            let external_identity = format!("spiffe://automata/overflow-{index}");
            sqlx::query(
                r"
                INSERT INTO runners (
                    id, tenant_id, group_id, name, normalized_name, labels,
                    capabilities, slots, status, generation, external_identity,
                    desired_state, created_at_ms, updated_at_ms
                )
                VALUES (
                    $1, 'capability-ceiling', $2, $3, $3, ARRAY['linux'],
                    $4, 2, 'offline', 1, $5, 'active', 2, 2
                )
                ",
            )
            .bind(runner_id.as_uuid())
            .bind(group_id)
            .bind(name)
            .bind(serde_json::to_value(capabilities)?)
            .bind(external_identity)
            .execute(database.pool())
            .await?;
        }

        assert!(matches!(
            database.store().verify_runner_capability_admission().await,
            Err(ProductBootstrapStoreError::ConfigurationDrift {
                resource: "runner capability admission"
            })
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn static_fleet_fails_closed_on_routing_and_revokes_unknown_active_authority() -> TestResult {
    run_with_database(|database| async move {
        let runner_id = RunnerId::new();
        let configured = fleet("drift-bootstrap", runner_id);
        database
            .store()
            .apply_static_runner_fleet(configured.clone())
            .await?;

        sqlx::query("UPDATE runners SET labels = ARRAY['broader'] WHERE id = $1")
            .bind(runner_id.as_uuid())
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database
                .store()
                .apply_static_runner_fleet(configured.clone())
                .await,
            Err(ProductBootstrapStoreError::ConfigurationDrift {
                resource: "runner registration"
            })
        ));

        sqlx::query("UPDATE runners SET labels = ARRAY['linux'] WHERE id = $1")
            .bind(runner_id.as_uuid())
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database
                .store()
                .apply_static_runner_fleet(fleet_with_certificates(
                    "drift-bootstrap",
                    runner_id,
                    &[(7, 2_000_000_001)],
                    1_000,
                ))
                .await,
            Err(ProductBootstrapStoreError::ConfigurationDrift {
                resource: "runner certificate authority"
            })
        ));
        sqlx::query(
            r"
            INSERT INTO runner_machine_certificates (
                leaf_sha256, runner_id, expires_at_seconds
            )
            VALUES ($1, $2, 2000000000)
            ",
        )
        .bind([8_u8; 32].as_slice())
        .bind(runner_id.as_uuid())
        .execute(database.pool())
        .await?;
        database
            .store()
            .apply_static_runner_fleet(configured)
            .await?;
        let revoked_at: Option<i64> = sqlx::query_scalar(
            "SELECT revoked_at_seconds FROM runner_machine_certificates WHERE leaf_sha256 = $1",
        )
        .bind([8_u8; 32].as_slice())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(revoked_at, Some(1));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn static_certificate_rotation_supports_overlap_then_one_way_revoke() -> TestResult {
    run_with_database(|database| async move {
        let runner_id = RunnerId::new();
        database
            .store()
            .apply_static_runner_fleet(fleet_with_certificates(
                "rotation-bootstrap",
                runner_id,
                &[(7, 2_000_000_000)],
                1_000,
            ))
            .await?;
        database
            .store()
            .apply_static_runner_fleet(fleet_with_certificates(
                "rotation-bootstrap",
                runner_id,
                &[(7, 2_000_000_000), (8, 2_100_000_000)],
                2_000,
            ))
            .await?;

        let overlap: Vec<(Vec<u8>, Option<i64>)> = sqlx::query_as(
            r"
            SELECT leaf_sha256, revoked_at_seconds
            FROM runner_machine_certificates
            WHERE runner_id = $1
            ORDER BY leaf_sha256
            ",
        )
        .bind(runner_id.as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(overlap.len(), 2);
        assert!(overlap.iter().all(|(_, revoked_at)| revoked_at.is_none()));

        database
            .store()
            .apply_static_runner_fleet(fleet_with_certificates(
                "rotation-bootstrap",
                runner_id,
                &[(8, 2_100_000_000)],
                3_000,
            ))
            .await?;
        database
            .store()
            .apply_static_runner_fleet(fleet_with_certificates(
                "rotation-bootstrap",
                runner_id,
                &[(8, 2_100_000_000)],
                4_000,
            ))
            .await?;
        let rotated: Vec<(Vec<u8>, Option<i64>)> = sqlx::query_as(
            r"
            SELECT leaf_sha256, revoked_at_seconds
            FROM runner_machine_certificates
            WHERE runner_id = $1
            ORDER BY leaf_sha256
            ",
        )
        .bind(runner_id.as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(rotated, vec![(vec![7; 32], Some(3)), (vec![8; 32], None)]);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn revoked_certificate_cannot_be_restored_by_stale_configuration() -> TestResult {
    run_with_database(|database| async move {
        let runner_id = RunnerId::new();
        database
            .store()
            .apply_static_runner_fleet(fleet_with_certificates(
                "resurrection-bootstrap",
                runner_id,
                &[(7, 2_000_000_000)],
                1_000,
            ))
            .await?;
        database
            .store()
            .apply_static_runner_fleet(fleet_with_certificates(
                "resurrection-bootstrap",
                runner_id,
                &[(8, 2_100_000_000)],
                2_000,
            ))
            .await?;
        assert!(matches!(
            database
                .store()
                .apply_static_runner_fleet(fleet_with_certificates(
                    "resurrection-bootstrap",
                    runner_id,
                    &[(7, 2_000_000_000), (8, 2_100_000_000)],
                    3_000,
                ))
                .await,
            Err(ProductBootstrapStoreError::ConfigurationDrift {
                resource: "runner certificate authority"
            })
        ));
        let durable: Vec<(Vec<u8>, Option<i64>)> = sqlx::query_as(
            r"
            SELECT leaf_sha256, revoked_at_seconds
            FROM runner_machine_certificates
            WHERE runner_id = $1
            ORDER BY leaf_sha256
            ",
        )
        .bind(runner_id.as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(durable, vec![(vec![7; 32], Some(2)), (vec![8; 32], None)]);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn certificate_identity_conflict_rolls_back_the_entire_fleet() -> TestResult {
    run_with_database(|database| async move {
        let authority_owner = RunnerId::new();
        database
            .store()
            .apply_static_runner_fleet(fleet("authority-owner", authority_owner))
            .await?;
        sqlx::query("UPDATE runners SET external_identity = $2 WHERE id = $1")
            .bind(authority_owner.as_uuid())
            .bind("spiffe://automata/authority-owner")
            .execute(database.pool())
            .await?;

        let conflicting_runner = RunnerId::new();
        assert!(matches!(
            database
                .store()
                .apply_static_runner_fleet(fleet_with_certificates(
                    "conflicting-fleet",
                    conflicting_runner,
                    &[(6, 2_000_000_000), (7, 2_000_000_000)],
                    2_000,
                ))
                .await,
            Err(ProductBootstrapStoreError::ConfigurationDrift {
                resource: "runner certificate authority"
            })
        ));
        let runner_exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM runners WHERE id = $1)")
                .bind(conflicting_runner.as_uuid())
                .fetch_one(database.pool())
                .await?;
        let tenant_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM tenants WHERE id = 'conflicting-fleet')",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(!runner_exists);
        assert!(!tenant_exists);
        let partially_inserted_leaf: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM runner_machine_certificates WHERE leaf_sha256 = $1)",
        )
        .bind([6_u8; 32].as_slice())
        .fetch_one(database.pool())
        .await?;
        assert!(!partially_inserted_leaf);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_replicas_converge_on_one_idempotent_fleet() -> TestResult {
    run_with_database(|database| async move {
        let configured = fleet("concurrent-bootstrap", RunnerId::new());
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let left_fleet = configured.clone();
        let (left, right) = tokio::join!(
            left_store.apply_static_runner_fleet(left_fleet),
            right_store.apply_static_runner_fleet(configured),
        );
        left?;
        right?;
        let runners: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM runners AS runner
            JOIN runner_groups AS runner_group ON runner_group.id = runner.group_id
            WHERE runner.tenant_id = 'concurrent-bootstrap'
              AND runner_group.normalized_name = 'g1'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        let certificates: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM runner_machine_certificates AS certificate
            JOIN runners AS runner ON runner.id = certificate.runner_id
            WHERE runner.tenant_id = 'concurrent-bootstrap'
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(runners, 1);
        assert_eq!(certificates, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn aborting_an_in_flight_fleet_transaction_rolls_back_and_allows_exact_retry() -> TestResult {
    run_with_database(|database| async move {
        const TENANT: &str = "aborted-bootstrap";

        let runner_id = RunnerId::new();
        let configured = fleet(TENANT, runner_id);
        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("LOCK TABLE runner_groups IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await?;

        let store = database.store().clone();
        let interrupted_fleet = configured.clone();
        let apply =
            tokio::spawn(async move { store.apply_static_runner_fleet(interrupted_fleet).await });
        let blocked_backend =
            match wait_for_backend_blocked_by(database.pool(), blocker_pid, "FROM runner_groups")
                .await
            {
                Ok(blocked_backend) => blocked_backend,
                Err(error) => {
                    blocker.rollback().await?;
                    apply.abort();
                    let _ = apply.await;
                    return Err(error);
                }
            };
        assert_ne!(blocked_backend, blocker_pid);
        assert!(!apply.is_finished());

        let tenant_visible: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)")
                .bind(TENANT)
                .fetch_one(database.pool())
                .await?;
        assert!(
            !tenant_visible,
            "the transaction's completed tenant insert must remain uncommitted while blocked"
        );

        apply.abort();
        let cancellation = tokio::time::timeout(Duration::from_secs(2), apply)
            .await
            .map_err(|_| "aborted fleet future did not stop")?
            .expect_err("aborted fleet future cannot complete");
        assert!(cancellation.is_cancelled());
        blocker.rollback().await?;

        let partial_state: (bool, bool, bool) =
            tokio::time::timeout(Duration::from_secs(5), async {
                sqlx::query_as(
                    r"
                SELECT
                    EXISTS (SELECT 1 FROM tenants WHERE id = $1),
                    EXISTS (SELECT 1 FROM runner_groups WHERE tenant_id = $1),
                    EXISTS (SELECT 1 FROM runners WHERE tenant_id = $1)
                ",
                )
                .bind(TENANT)
                .fetch_one(database.pool())
                .await
            })
            .await
            .map_err(|_| "aborted transaction did not release its connection and locks")??;
        assert_eq!(partial_state, (false, false, false));

        tokio::time::timeout(
            Duration::from_secs(5),
            database.store().apply_static_runner_fleet(configured),
        )
        .await
        .map_err(|_| "exact retry remained blocked behind the aborted transaction")??;
        let durable: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM tenants WHERE id = $1),
                (SELECT count(*) FROM runner_groups WHERE tenant_id = $1),
                (SELECT count(*) FROM runners WHERE tenant_id = $1)
            ",
        )
        .bind(TENANT)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable, (1, 1, 1));
        let certificate_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_machine_certificates WHERE runner_id = $1",
        )
        .bind(runner_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(certificate_count, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn undeclared_group_member_is_fatal_instead_of_broadening_routing() -> TestResult {
    run_with_database(|database| async move {
        let configured = fleet("membership-bootstrap", RunnerId::new());
        database
            .store()
            .apply_static_runner_fleet(configured.clone())
            .await?;
        let group_id: uuid::Uuid = sqlx::query_scalar(
            "SELECT id FROM runner_groups WHERE tenant_id = 'membership-bootstrap' AND normalized_name = 'g1'",
        )
        .fetch_one(database.pool())
        .await?;
        let extra_id = RunnerId::new();
        let extra_capabilities = RunnerCapabilities::new(
            extra_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_labels([RunnerLabel::new("linux")?])
        .with_groups([RunnerGroup::new("g1")?])
        .with_max_parallel_jobs(2)?;
        sqlx::query(
            r"
            INSERT INTO runners (
                id, tenant_id, group_id, name, normalized_name, labels,
                capabilities, slots, status, generation, external_identity,
                desired_state, created_at_ms, updated_at_ms
            )
            VALUES (
                $1, 'membership-bootstrap', $2, 'undeclared', 'undeclared',
                ARRAY['linux'], $3, 2, 'offline', 1,
                'spiffe://automata/undeclared', 'active', 2, 2
            )
            ",
        )
        .bind(extra_id.as_uuid())
        .bind(group_id)
        .bind(serde_json::to_value(extra_capabilities)?)
        .execute(database.pool())
        .await?;

        assert!(matches!(
            database.store().apply_static_runner_fleet(configured).await,
            Err(ProductBootstrapStoreError::ConfigurationDrift {
                resource: "runner group membership"
            })
        ));
        Ok(())
    })
    .await
}

async fn wait_for_backend_blocked_by(
    pool: &sqlx::PgPool,
    blocking_backend_pid: i32,
    query_fragment: &str,
) -> TestResult<i32> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
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
    })
    .await
    .map_err(|_| format!("backend did not block on expected {query_fragment} lock"))?
}
