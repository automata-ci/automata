mod support;

use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_auth::{
    authorization::{
        AuthorizationScope, Permission, RepositoryResource, RepositoryResourceId, RoleName,
    },
    human::{PrincipalId, TenantId},
    management::{
        ChangeMemberStatus, CreateRole, DeleteRole, DirectBindingGrantOptionCollection,
        DirectBindingGrantOptionsState, GrantRole, HumanRbacManagementRepository,
        ListManagementRecords, ListManagementRoleBindings, ManagedPrincipalId, ManagementActor,
        ManagementDetailOutcome, ManagementMutationOutcome, ManagementPageSize,
        ManagementReadOutcome, ManagementRepositoryError, ManagementRequestId, ManagementRevision,
        ManagementRoleBindingSource, MemberStatus, ProviderRoleMappingId,
        ReadDirectBindingGrantOptions, ReadManagementMutationCapabilities, ReadMemberDetail,
        ReadRoleDetail, RevokeRole, RoleBindingId, RoleId, SetRolePermission, UpdateRole,
        permissions,
    },
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_auth_postgres::{
    PostgresHumanRbacManagementRepository,
    management::{
        ConsumeRunnerEnrollment, CreateRunnerEnrollmentToken,
        MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS, MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS,
        PrepareRunnerEnrollment, RunnerEnrollmentConsumeOutcome, RunnerEnrollmentPrepareOutcome,
    },
};
use automata_ci_core::{
    Architecture, MAX_REGISTERED_RUNNERS, OperatingSystem, RunnerCapabilities, RunnerGroup,
    RunnerId, RunnerLabel, RunnerPlatform, Sha256Digest,
};
use automata_ci_postgres_test_support::TestClock;
use automata_ci_runner_auth::RunnerMachineDirectory as _;
use automata_ci_runner_auth_postgres::PostgresRunnerMachineDirectory;
use sqlx::PgPool;
use uuid::Uuid;

use support::{TestResult, run_with_database};

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("test UUID")
}

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).expect("tenant")
}

fn principal(value: Uuid) -> PrincipalId {
    PrincipalId::new(value.hyphenated().to_string()).expect("principal")
}

fn managed_principal(value: Uuid) -> ManagedPrincipalId {
    ManagedPrincipalId::from_uuid(value).expect("managed principal")
}

fn role(value: Uuid) -> RoleId {
    RoleId::from_uuid(value).expect("role")
}

fn binding(value: Uuid) -> RoleBindingId {
    RoleBindingId::from_uuid(value).expect("binding")
}

fn revision(value: i64) -> ManagementRevision {
    ManagementRevision::new(u64::try_from(value).expect("nonnegative revision"))
        .expect("positive revision")
}

fn actor(
    tenant_id: &str,
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: i64,
    request_id: &str,
) -> ManagementActor {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_secs();
    actor_at(
        tenant_id,
        principal_id,
        session_id,
        authorization_revision,
        request_id,
        UnixTimestamp::from_seconds(now),
    )
}

fn actor_at(
    tenant_id: &str,
    principal_id: Uuid,
    session_id: Uuid,
    authorization_revision: i64,
    request_id: &str,
    now: UnixTimestamp,
) -> ManagementActor {
    ManagementActor::new(
        tenant(tenant_id),
        principal(principal_id),
        SessionId::new(session_id.hyphenated().to_string()).expect("session"),
        revision(authorization_revision),
        Some(ManagementRequestId::new(request_id).expect("request ID")),
        now,
    )
}

async fn seed_tenant(pool: &PgPool, tenant_id: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,$1,100000,100000)",
    )
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_member(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    subject: &str,
    login: &str,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO human_principals (
            id,status,display_name,created_at_ms,updated_at_ms
        ) VALUES ($1,'active',$2,100000,100000)
        ",
    )
    .bind(principal_id)
    .bind(format!("{login} display"))
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id,provider_id,provider_subject,provider_login,
            normalized_login,display_name,first_authenticated_at_ms,
            last_authenticated_at_ms,last_observed_at_ms,created_at_ms,updated_at_ms
        ) VALUES ($1,'github',$2,$3,$3,$4,100000,100000,100000,100000,100000)
        ",
    )
    .bind(principal_id)
    .bind(subject)
    .bind(login)
    .bind(format!("{login} provider"))
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id,principal_id,status,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'active',100000,100000)
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_role(
    pool: &PgPool,
    tenant_id: &str,
    role_id: Uuid,
    name: &str,
    immutable: bool,
    permissions: &[&str],
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id,id,name,display_name,role_kind,immutable,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,$3,$3,'custom',$4,100000,100000)
        ",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(name)
    .bind(immutable)
    .execute(pool)
    .await?;
    for permission in permissions {
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id,role_id,permission_name,granted_at_ms
            ) VALUES ($1,$2,$3,100000)
            ",
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(permission)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn seed_binding(
    pool: &PgPool,
    tenant_id: &str,
    binding_id: Uuid,
    principal_id: Uuid,
    role_id: Uuid,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id,id,principal_id,role_id,scope_kind,
            assignment_source,status,created_at_ms
        ) VALUES ($1,$2,$3,$4,'tenant','manual','active',100000)
        ",
    )
    .bind(tenant_id)
    .bind(binding_id)
    .bind(principal_id)
    .bind(role_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn authorization_revision(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        r"
        SELECT authorization_revision
        FROM tenant_human_memberships
        WHERE tenant_id=$1 AND principal_id=$2
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_one(pool)
    .await?)
}

async fn membership_revision(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_one(pool)
    .await?)
}

async fn seed_session(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    session_id: Uuid,
) -> TestResult<i64> {
    let current_revision = authorization_revision(pool, tenant_id, principal_id).await?;
    let subject: String = sqlx::query_scalar(
        "SELECT provider_subject FROM human_provider_identities WHERE principal_id=$1 AND provider_id='github'",
    )
    .bind(principal_id)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id,tenant_id,principal_id,provider_id,provider_subject,
            session_kind,audience,token_hash,token_hash_key_id,
            authorization_revision,issued_at_ms,last_seen_at_ms,
            idle_expires_at_ms,expires_at_ms
        ) VALUES ($1,$2,$3,'github',$4,'browser','automata.web',
                  $5,$6,$7,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 100000,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 100000,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 500000,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 1000000)
        ",
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(principal_id)
    .bind(subject)
    .bind(session_id.as_bytes().repeat(2))
    .bind(format!("management-{session_id}"))
    .bind(current_revision)
    .execute(pool)
    .await?;
    Ok(current_revision)
}

async fn seed_cli_session(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    session_id: Uuid,
    lifecycle_status: &str,
    future_activation: bool,
) -> TestResult<i64> {
    let current_revision = authorization_revision(pool, tenant_id, principal_id).await?;
    let subject: String = sqlx::query_scalar(
        "SELECT provider_subject FROM human_provider_identities WHERE principal_id=$1 AND provider_id='github'",
    )
    .bind(principal_id)
    .fetch_one(pool)
    .await?;
    let database_time_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000")
            .fetch_one(pool)
            .await?;
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id,tenant_id,principal_id,provider_id,provider_subject,
            session_kind,audience,token_hash,token_hash_key_id,
            authorization_revision,issued_at_ms,last_seen_at_ms,
            idle_expires_at_ms,expires_at_ms,lifecycle_status,
            activation_deadline_ms,activated_at_ms
        ) VALUES ($1,$2,$3,'github',$4,'cli','automata.cli',$5,$6,$7,
                  $8,$8,$9,$10,$11,$12,$13)
        ",
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(principal_id)
    .bind(subject)
    .bind(session_id.as_bytes().repeat(2))
    .bind(format!("management-cli-{session_id}"))
    .bind(current_revision)
    .bind(database_time_ms - 10_000)
    .bind(database_time_ms + 500_000)
    .bind(database_time_ms + 600_000)
    .bind("pending_activation")
    .bind(database_time_ms + 290_000)
    .bind(None::<i64>)
    .execute(pool)
    .await?;
    if lifecycle_status == "active" {
        sqlx::query(
            "UPDATE human_sessions SET lifecycle_status='active',activated_at_ms=$2,revision=revision+1 WHERE id=$1",
        )
        .bind(session_id)
        .bind(future_activation.then_some(database_time_ms + 30_000))
        .execute(pool)
        .await?;
    }
    Ok(current_revision)
}

#[allow(clippy::too_many_arguments)]
async fn seed_grant_scenario(
    pool: &PgPool,
    tenant_id: &str,
    manager: Uuid,
    target: Uuid,
    manager_role: Uuid,
    target_role: Uuid,
    manager_binding: Uuid,
    session_id: Uuid,
) -> TestResult<i64> {
    seed_tenant(pool, tenant_id).await?;
    let manager_subject = (manager.as_u128() % 100_000 + 1).to_string();
    let target_subject = (target.as_u128() % 100_000 + 1).to_string();
    seed_member(pool, tenant_id, manager, &manager_subject, "manager").await?;
    seed_member(pool, tenant_id, target, &target_subject, "target").await?;
    seed_role(
        pool,
        tenant_id,
        manager_role,
        "binding-manager",
        false,
        &[permissions::ROLE_BINDINGS_MANAGE],
    )
    .await?;
    seed_role(pool, tenant_id, target_role, "granted-role", false, &[]).await?;
    seed_binding(pool, tenant_id, manager_binding, manager, manager_role).await?;
    seed_session(pool, tenant_id, manager, session_id).await
}

async fn audit_count(pool: &PgPool, request_id: &str) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM security_audit_events WHERE request_id=$1")
            .bind(request_id)
            .fetch_one(pool)
            .await?,
    )
}

async fn wait_for_blocked_transaction(pool: &PgPool) -> TestResult<bool> {
    for _ in 0..200 {
        let blocked: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM pg_stat_activity
                WHERE datname=current_database()
                  AND pid<>pg_backend_pid()
                  AND cardinality(pg_blocking_pids(pid))>0
            )
            ",
        )
        .fetch_one(pool)
        .await?;
        if blocked {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(false)
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn cli_actor_lifecycle_is_authority_for_reads_and_mutations() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa91");
        seed_member(pool, "tenant-a", manager, "9101", "cli-manager").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000091");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "cli-manager",
            false,
            &[permissions::ROLES_READ, permissions::ROLES_MANAGE],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000091"),
            manager,
            manager_role,
        )
        .await?;
        let pending_session = uuid("30000000-0000-4000-8000-000000000091");
        let pending_revision = seed_cli_session(
            pool,
            "tenant-a",
            manager,
            pending_session,
            "pending_activation",
            false,
        )
        .await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        assert_eq!(
            repository
                .read_role_detail(&ReadRoleDetail::new(
                    actor(
                        "tenant-a",
                        manager,
                        pending_session,
                        pending_revision,
                        "pending-cli-read",
                    ),
                    role(manager_role),
                ))
                .await?,
            ManagementDetailOutcome::Forbidden
        );
        assert_eq!(
            repository
                .create_role(CreateRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        pending_session,
                        pending_revision,
                        "pending-cli-mutation",
                    ),
                    role(uuid("40000000-0000-4000-8000-000000000091")),
                    RoleName::new("pending-cli-role")?,
                    "Pending CLI role",
                )?)
                .await?,
            ManagementMutationOutcome::Forbidden
        );

        let future_session = uuid("50000000-0000-4000-8000-000000000091");
        let future_revision =
            seed_cli_session(pool, "tenant-a", manager, future_session, "active", true).await?;
        assert_eq!(
            repository
                .read_role_detail(&ReadRoleDetail::new(
                    actor(
                        "tenant-a",
                        manager,
                        future_session,
                        future_revision,
                        "future-cli-read",
                    ),
                    role(manager_role),
                ))
                .await
                .expect_err("a future CLI activation is corrupt authority"),
            ManagementRepositoryError::CorruptData
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn finite_grants_rebase_both_accepted_clock_skews_without_extending_lifetime() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let scenarios = [
            (
                "tenant-positive-skew",
                59_i64,
                uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa92"),
                uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbb92"),
                uuid("10000000-0000-4000-8000-000000000092"),
                uuid("11000000-0000-4000-8000-000000000092"),
                uuid("20000000-0000-4000-8000-000000000092"),
                uuid("30000000-0000-4000-8000-000000000092"),
                uuid("40000000-0000-4000-8000-000000000092"),
            ),
            (
                "tenant-negative-skew",
                -59_i64,
                uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa93"),
                uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbb93"),
                uuid("10000000-0000-4000-8000-000000000093"),
                uuid("11000000-0000-4000-8000-000000000093"),
                uuid("20000000-0000-4000-8000-000000000093"),
                uuid("30000000-0000-4000-8000-000000000093"),
                uuid("40000000-0000-4000-8000-000000000093"),
            ),
        ];
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        for (
            tenant_id,
            skew,
            manager,
            target,
            manager_role,
            target_role,
            manager_binding,
            session_id,
            granted_binding,
        ) in scenarios
        {
            let manager_revision = seed_grant_scenario(
                pool,
                tenant_id,
                manager,
                target,
                manager_role,
                target_role,
                manager_binding,
                session_id,
            )
            .await?;
            let system_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();
            let caller_seconds = if skew >= 0 {
                system_now.checked_add(u64::try_from(skew)?)
            } else {
                system_now.checked_sub(skew.unsigned_abs())
            }
            .ok_or("test timestamp overflow")?;
            let caller_now = UnixTimestamp::from_seconds(caller_seconds);
            let outcome = repository
                .grant_role(GrantRole::new(
                    actor_at(
                        tenant_id,
                        manager,
                        session_id,
                        manager_revision,
                        if skew > 0 {
                            "positive-skew-grant"
                        } else {
                            "negative-skew-grant"
                        },
                        caller_now,
                    ),
                    binding(granted_binding),
                    managed_principal(target),
                    role(target_role),
                    AuthorizationScope::tenant(tenant(tenant_id)),
                    Some(caller_now.checked_add(120)?),
                )?)
                .await?;
            assert!(matches!(outcome, ManagementMutationOutcome::Applied(_)));
            let persisted: (i64, i64) = sqlx::query_as(
                "SELECT created_at_ms,valid_until_ms FROM rbac_role_bindings WHERE tenant_id=$1 AND id=$2",
            )
            .bind(tenant_id)
            .bind(granted_binding)
            .fetch_one(pool)
            .await?;
            let persisted_lifetime_ms = persisted.1 - persisted.0;
            assert!(
                (1..=120_000).contains(&persisted_lifetime_ms),
                "the rebased lifetime must remain positive without exceeding the request"
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn finite_grant_expiring_while_waiting_for_target_lock_is_rejected() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa94");
        let target = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbb94");
        let manager_role = uuid("10000000-0000-4000-8000-000000000094");
        let target_role = uuid("11000000-0000-4000-8000-000000000094");
        let manager_revision = seed_grant_scenario(
            pool,
            "tenant-lock-expiry",
            manager,
            target,
            manager_role,
            target_role,
            uuid("20000000-0000-4000-8000-000000000094"),
            uuid("30000000-0000-4000-8000-000000000094"),
        )
        .await?;
        let mut gate = pool.begin().await?;
        sqlx::query(
            "SELECT principal_id FROM tenant_human_memberships WHERE tenant_id='tenant-lock-expiry' AND principal_id=$1 FOR UPDATE",
        )
        .bind(target)
        .execute(&mut *gate)
        .await?;
        let caller_now = UnixTimestamp::from_seconds(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
        );
        let granted_binding = uuid("40000000-0000-4000-8000-000000000094");
        let command = GrantRole::new(
            actor_at(
                "tenant-lock-expiry",
                manager,
                uuid("30000000-0000-4000-8000-000000000094"),
                manager_revision,
                "grant-expired-after-lock",
                caller_now,
            ),
            binding(granted_binding),
            managed_principal(target),
            role(target_role),
            AuthorizationScope::tenant(tenant("tenant-lock-expiry")),
            Some(caller_now.checked_add(2)?),
        )?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let mutation = tokio::spawn(async move { repository.grant_role(command).await });
        if !wait_for_blocked_transaction(pool).await? {
            gate.rollback().await?;
            return Err("grant did not wait on its exact target membership lock".into());
        }
        clock.advance(2_100).await?;
        gate.commit().await?;
        assert_eq!(
            mutation
                .await?
                .expect_err("an expired finite grant must not commit"),
            ManagementRepositoryError::InvalidRequest
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rbac_role_bindings WHERE tenant_id='tenant-lock-expiry' AND id=$1",
        )
        .bind(granted_binding)
        .fetch_one(pool)
        .await?;
        assert_eq!(count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn sign_in_and_management_share_a_deadlock_free_principal_identity_membership_order()
-> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa8");
        seed_member(pool, "tenant-a", manager, "9801", "order-manager").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000098");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "order-manager",
            false,
            &[permissions::ROLES_MANAGE],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000098"),
            manager,
            manager_role,
        )
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000098");
        let manager_revision = seed_session(pool, "tenant-a", manager, session_id).await?;

        // Model sign-in's explicit principal -> identity -> membership locks.
        let mut sign_in = pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='750ms'")
            .execute(&mut *sign_in)
            .await?;
        sqlx::query("SELECT id FROM human_principals WHERE id=$1 FOR UPDATE")
            .bind(manager)
            .execute(&mut *sign_in)
            .await?;

        let role_id = uuid("40000000-0000-4000-8000-000000000098");
        let command = CreateRole::new(
            actor(
                "tenant-a",
                manager,
                session_id,
                manager_revision,
                "canonical-lock-order",
            ),
            role(role_id),
            RoleName::new("ordered-role")?,
            "Ordered role",
        )?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let mutation = tokio::spawn(async move { repository.create_role(command).await });
        if !wait_for_blocked_transaction(pool).await? {
            sign_in.rollback().await?;
            return Err(format!(
                "management did not block at the actor principal: {:?}",
                mutation.await?
            )
            .into());
        }

        // Management must not have skipped ahead to either later authority row.
        sqlx::query(
            r"
            SELECT principal_id FROM human_provider_identities
            WHERE principal_id=$1 AND provider_id='github' AND provider_subject='9801'
            FOR UPDATE
            ",
        )
        .bind(manager)
        .execute(&mut *sign_in)
        .await?;
        sqlx::query(
            r"
            SELECT principal_id FROM tenant_human_memberships
            WHERE tenant_id='tenant-a' AND principal_id=$1
            FOR UPDATE
            ",
        )
        .bind(manager)
        .execute(&mut *sign_in)
        .await?;
        sign_in.commit().await?;

        assert!(matches!(
            mutation.await??,
            ManagementMutationOutcome::Applied(_)
        ));
        let created: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM rbac_roles WHERE tenant_id='tenant-a' AND id=$1)",
        )
        .bind(role_id)
        .fetch_one(pool)
        .await?;
        assert!(created);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn mutation_resamples_database_time_after_exact_lock_wait() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9");
        let target = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb9");
        seed_member(pool, "tenant-a", manager, "9901", "clock-manager").await?;
        seed_member(pool, "tenant-a", target, "9902", "lock-target").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000099");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "clock-manager",
            false,
            &[permissions::ROLES_MANAGE],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000099"),
            manager,
            manager_role,
        )
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000099");
        let manager_revision = seed_session(pool, "tenant-a", manager, session_id).await?;
        sqlx::query(
            r"
            UPDATE human_sessions
            SET idle_expires_at_ms =
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 2000
            WHERE id=$1
            ",
        )
        .bind(session_id)
        .execute(pool)
        .await?;

        let mut gate = pool.begin().await?;
        sqlx::query(
            r"
            SELECT principal_id
            FROM tenant_human_memberships
            WHERE tenant_id='tenant-a' AND principal_id=$1
            FOR UPDATE
            ",
        )
        .bind(target)
        .execute(&mut *gate)
        .await?;

        let role_id = uuid("40000000-0000-4000-8000-000000000099");
        let command = CreateRole::new(
            actor(
                "tenant-a",
                manager,
                session_id,
                manager_revision,
                "post-lock-expiry",
            ),
            role(role_id),
            RoleName::new("late-role")?,
            "Late role",
        )?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let mutation = tokio::spawn(async move { repository.create_role(command).await });
        if !wait_for_blocked_transaction(pool).await? {
            gate.rollback().await?;
            return Err(format!(
                "management mutation did not wait on the exact membership lock: {:?}",
                mutation.await?
            )
            .into());
        }
        clock.advance(2_100).await?;
        gate.commit().await?;

        assert_eq!(mutation.await??, ManagementMutationOutcome::Forbidden);
        let role_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rbac_roles WHERE tenant_id='tenant-a' AND id=$1",
        )
        .bind(role_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(role_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn mutation_rechecks_expiring_permission_after_exact_target_lock_wait() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa7");
        let target = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb7");
        seed_member(pool, "tenant-a", manager, "9701", "expiring-manager").await?;
        seed_member(pool, "tenant-a", target, "9702", "lock-target").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000097");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "expiring-manager",
            false,
            &[permissions::ROLES_MANAGE],
        )
        .await?;
        let manager_binding = uuid("20000000-0000-4000-8000-000000000097");
        seed_binding(pool, "tenant-a", manager_binding, manager, manager_role).await?;
        sqlx::query(
            r"
            UPDATE rbac_role_bindings
            SET valid_until_ms =
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 2000
            WHERE tenant_id='tenant-a' AND id=$1
            ",
        )
        .bind(manager_binding)
        .execute(pool)
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000097");
        let manager_revision = seed_session(pool, "tenant-a", manager, session_id).await?;

        let mut gate = pool.begin().await?;
        sqlx::query(
            r"
            SELECT principal_id
            FROM tenant_human_memberships
            WHERE tenant_id='tenant-a' AND principal_id=$1
            FOR UPDATE
            ",
        )
        .bind(target)
        .execute(&mut *gate)
        .await?;

        let role_id = uuid("40000000-0000-4000-8000-000000000097");
        let command = CreateRole::new(
            actor(
                "tenant-a",
                manager,
                session_id,
                manager_revision,
                "expired-permission-after-lock",
            ),
            role(role_id),
            RoleName::new("late-permission-role")?,
            "Late permission role",
        )?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let mutation = tokio::spawn(async move { repository.create_role(command).await });
        if !wait_for_blocked_transaction(pool).await? {
            gate.rollback().await?;
            return Err(format!(
                "management mutation did not wait on the exact membership lock: {:?}",
                mutation.await?
            )
            .into());
        }
        clock.advance(2_100).await?;
        gate.commit().await?;

        assert_eq!(mutation.await??, ManagementMutationOutcome::Forbidden);
        let role_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rbac_roles WHERE tenant_id='tenant-a' AND id=$1",
        )
        .bind(role_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(role_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn permission_authority_is_exact_and_stale_sessions_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let named_admin = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        seed_member(pool, "tenant-a", manager, "101", "manager").await?;
        seed_member(pool, "tenant-a", named_admin, "102", "named-admin").await?;

        let manager_role = uuid("10000000-0000-4000-8000-000000000001");
        let empty_admin_role = uuid("10000000-0000-4000-8000-000000000002");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "manager-capabilities",
            false,
            &[
                permissions::ROLES_MANAGE,
                permissions::MEMBERS_MANAGE,
                permissions::ROLE_BINDINGS_MANAGE,
                permissions::ROLES_READ,
                permissions::MEMBERS_READ,
            ],
        )
        .await?;
        seed_role(
            pool,
            "tenant-a",
            empty_admin_role,
            "administrator",
            false,
            &[],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000001"),
            manager,
            manager_role,
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000002"),
            named_admin,
            empty_admin_role,
        )
        .await?;

        let manager_session = uuid("30000000-0000-4000-8000-000000000001");
        let named_admin_session = uuid("30000000-0000-4000-8000-000000000002");
        let manager_revision = seed_session(pool, "tenant-a", manager, manager_session).await?;
        let named_admin_revision =
            seed_session(pool, "tenant-a", named_admin, named_admin_session).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());

        let denied = repository
            .create_role(
                CreateRole::new(
                    actor(
                        "tenant-a",
                        named_admin,
                        named_admin_session,
                        named_admin_revision,
                        "no-name-bypass",
                    ),
                    role(uuid("40000000-0000-4000-8000-000000000001")),
                    RoleName::new("forbidden-role").expect("role name"),
                    "Forbidden role",
                )
                .expect("command"),
            )
            .await?;
        assert!(matches!(denied, ManagementMutationOutcome::Forbidden));
        assert_eq!(audit_count(pool, "no-name-bypass").await?, 1);

        sqlx::query(
            "DELETE FROM rbac_role_permissions WHERE tenant_id='tenant-a' AND role_id=$1 AND permission_name=$2",
        )
        .bind(manager_role)
        .bind(permissions::ROLES_READ)
        .execute(pool)
        .await?;
        let stale = repository
            .create_role(
                CreateRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        manager_session,
                        manager_revision,
                        "stale-session",
                    ),
                    role(uuid("40000000-0000-4000-8000-000000000002")),
                    RoleName::new("stale-role").expect("role name"),
                    "Stale role",
                )
                .expect("command"),
            )
            .await?;
        assert!(matches!(stale, ManagementMutationOutcome::SessionStale));
        assert_eq!(audit_count(pool, "stale-session").await?, 1);
        let created: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM rbac_roles WHERE tenant_id='tenant-a' AND name='stale-role')",
        )
        .fetch_one(pool)
        .await?;
        assert!(!created);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn mapped_github_authority_uses_only_the_newest_unexpired_numeric_snapshot() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let mapped_manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        seed_member(pool, "tenant-a", mapped_manager, "601", "mapped-manager").await?;
        let mapped_role = uuid("10000000-0000-4000-8000-000000000051");
        seed_role(
            pool,
            "tenant-a",
            mapped_role,
            "mapped-manager",
            false,
            &[permissions::ROLES_MANAGE],
        )
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_role_mappings (
                tenant_id,id,organization_id,organization_login,role_id,
                scope_kind,status,created_at_ms,updated_at_ms
            ) VALUES ('tenant-a',$1,7001,'renamable-org',$2,
                      'tenant','active',100000,100000)
            ",
        )
        .bind(uuid("50000000-0000-4000-8000-000000000051"))
        .bind(mapped_role)
        .execute(pool)
        .await?;
        let first_snapshot = uuid("60000000-0000-4000-8000-000000000051");
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','601',1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 200000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 100000
            )
            ",
        )
        .bind(first_snapshot)
        .bind(mapped_manager)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id,snapshot_id,organization_id,organization_login,membership_role
            ) VALUES ('tenant-a',$1,7001,'new-org-login','member')
            ",
        )
        .bind(first_snapshot)
        .execute(pool)
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000051");
        let current_revision = seed_session(pool, "tenant-a", mapped_manager, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());

        let valid = repository
            .create_role(CreateRole::new(
                actor(
                    "tenant-a",
                    mapped_manager,
                    session_id,
                    current_revision,
                    "mapped-valid",
                ),
                role(uuid("40000000-0000-4000-8000-000000000051")),
                RoleName::new("mapped-created").expect("role name"),
                "Mapped created",
            )?)
            .await?;
        assert!(matches!(valid, ManagementMutationOutcome::Applied(_)));

        let newer_without_membership = uuid("60000000-0000-4000-8000-000000000052");
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','601',1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 100000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 100000
            )
            ",
        )
        .bind(newer_without_membership)
        .bind(mapped_manager)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET authorization_revision=authorization_revision+1
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(mapped_manager)
        .execute(pool)
        .await?;
        let empty_session_id = uuid("30000000-0000-4000-8000-000000000052");
        let empty_revision =
            seed_session(pool, "tenant-a", mapped_manager, empty_session_id).await?;
        let removed = repository
            .create_role(CreateRole::new(
                actor(
                    "tenant-a",
                    mapped_manager,
                    empty_session_id,
                    empty_revision,
                    "mapped-newer-empty",
                ),
                role(uuid("40000000-0000-4000-8000-000000000052")),
                RoleName::new("must-not-exist-a").expect("role name"),
                "Must not exist",
            )?)
            .await?;
        assert!(matches!(removed, ManagementMutationOutcome::Forbidden));

        let expired_snapshot = uuid("60000000-0000-4000-8000-000000000053");
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','601',1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 50000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 10000
            )
            ",
        )
        .bind(expired_snapshot)
        .bind(mapped_manager)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id,snapshot_id,organization_id,organization_login,membership_role
            ) VALUES ('tenant-a',$1,7001,'another-rename','member')
            ",
        )
        .bind(expired_snapshot)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET authorization_revision=authorization_revision+1
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(mapped_manager)
        .execute(pool)
        .await?;
        let expired_session_id = uuid("30000000-0000-4000-8000-000000000053");
        let expired_revision =
            seed_session(pool, "tenant-a", mapped_manager, expired_session_id).await?;
        let expired = repository
            .create_role(CreateRole::new(
                actor(
                    "tenant-a",
                    mapped_manager,
                    expired_session_id,
                    expired_revision,
                    "mapped-expired",
                ),
                role(uuid("40000000-0000-4000-8000-000000000053")),
                RoleName::new("must-not-exist-b").expect("role name"),
                "Must not exist",
            )?)
            .await?;
        assert!(matches!(expired, ManagementMutationOutcome::Forbidden));
        for request_id in ["mapped-valid", "mapped-newer-empty", "mapped-expired"] {
            assert_eq!(audit_count(pool, request_id).await?, 1);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn immutable_conflict_reference_and_last_manager_attempts_are_audited() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        seed_member(pool, "tenant-a", manager, "201", "manager").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000011");
        let manager_binding = uuid("20000000-0000-4000-8000-000000000011");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "manager",
            false,
            &[
                permissions::ROLES_MANAGE,
                permissions::MEMBERS_MANAGE,
                permissions::ROLE_BINDINGS_MANAGE,
            ],
        )
        .await?;
        seed_binding(pool, "tenant-a", manager_binding, manager, manager_role).await?;
        let immutable_role = uuid("10000000-0000-4000-8000-000000000012");
        seed_role(
            pool,
            "tenant-a",
            immutable_role,
            "custom-immutable",
            true,
            &[],
        )
        .await?;
        let mapped_role = uuid("10000000-0000-4000-8000-000000000013");
        seed_role(pool, "tenant-a", mapped_role, "mapped", false, &[]).await?;
        sqlx::query(
            r"
            INSERT INTO github_role_mappings (
                tenant_id,id,organization_id,organization_login,role_id,
                scope_kind,status,created_at_ms,updated_at_ms
            ) VALUES ('tenant-a',$1,44,'automata-ci',$2,'tenant','active',100000,100000)
            ",
        )
        .bind(uuid("50000000-0000-4000-8000-000000000001"))
        .bind(mapped_role)
        .execute(pool)
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000011");
        let current_revision = seed_session(pool, "tenant-a", manager, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());

        let immutable = repository
            .update_role(
                UpdateRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "immutable-role",
                    ),
                    role(immutable_role),
                    revision(1),
                    "Changed",
                )
                .expect("command"),
            )
            .await?;
        assert!(matches!(immutable, ManagementMutationOutcome::Immutable));

        let referenced = repository
            .delete_role(DeleteRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "mapped-role",
                ),
                role(mapped_role),
                revision(1),
            ))
            .await?;
        assert!(matches!(
            referenced,
            ManagementMutationOutcome::ResourceInUse
        ));

        let last_permission = repository
            .set_role_permission(SetRolePermission::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "last-permission",
                ),
                role(manager_role),
                revision(1),
                Permission::new(permissions::ROLES_MANAGE).expect("permission"),
                false,
            ))
            .await?;
        assert!(matches!(
            last_permission,
            ManagementMutationOutcome::LastManager
        ));

        let last_binding = repository
            .revoke_role(
                RevokeRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "last-binding",
                    ),
                    binding(manager_binding),
                    revision(1),
                    "retain the last manager",
                )
                .expect("command"),
            )
            .await?;
        assert!(matches!(
            last_binding,
            ManagementMutationOutcome::LastManager
        ));

        let self_suspend = repository
            .change_member_status(
                ChangeMemberStatus::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "self-suspend",
                    ),
                    managed_principal(manager),
                    revision(membership_revision(pool, "tenant-a", manager).await?),
                    MemberStatus::Suspended,
                    Some("self suspension must fail".to_owned()),
                )
                .expect("command"),
            )
            .await?;
        assert!(matches!(
            self_suspend,
            ManagementMutationOutcome::SelfModificationForbidden
        ));

        for request_id in [
            "immutable-role",
            "mapped-role",
            "last-permission",
            "last-binding",
            "self-suspend",
        ] {
            assert_eq!(audit_count(pool, request_id).await?, 1);
        }
        let outcomes: Vec<String> = sqlx::query_scalar(
            r"
            SELECT outcome FROM security_audit_events
            WHERE request_id = ANY($1)
            ORDER BY request_id
            ",
        )
        .bind(vec![
            "immutable-role",
            "mapped-role",
            "last-permission",
            "last-binding",
            "self-suspend",
        ])
        .fetch_all(pool)
        .await?;
        assert_eq!(outcomes, vec!["denied"; 5]);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn audit_failure_rolls_back_mutation_and_success_audit_is_sanitized() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        seed_member(pool, "tenant-a", manager, "301", "manager").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000021");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "manager",
            false,
            &[permissions::ROLES_MANAGE, permissions::MEMBERS_MANAGE],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000021"),
            manager,
            manager_role,
        )
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000021");
        let current_revision = seed_session(pool, "tenant-a", manager, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        sqlx::query(
            r"
            CREATE FUNCTION reject_management_audit() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit unavailable' USING ERRCODE='check_violation';
            END;
            $$ LANGUAGE plpgsql
            ",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            CREATE TRIGGER reject_management_audit
            BEFORE INSERT ON security_audit_events
            FOR EACH ROW EXECUTE FUNCTION reject_management_audit()
            ",
        )
        .execute(pool)
        .await?;

        let role_id = uuid("40000000-0000-4000-8000-000000000021");
        let failed = repository
            .create_role(
                CreateRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "audit-rollback",
                    ),
                    role(role_id),
                    RoleName::new("atomic-audit").expect("role name"),
                    "never-store-this-display-secret",
                )
                .expect("command"),
            )
            .await;
        assert!(failed.is_err());
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM rbac_roles WHERE tenant_id='tenant-a' AND id=$1)",
        )
        .bind(role_id)
        .fetch_one(pool)
        .await?;
        assert!(!exists);

        sqlx::query("DROP TRIGGER reject_management_audit ON security_audit_events")
            .execute(pool)
            .await?;
        sqlx::query("DROP FUNCTION reject_management_audit()")
            .execute(pool)
            .await?;
        let applied = repository
            .create_role(
                CreateRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "audit-success",
                    ),
                    role(role_id),
                    RoleName::new("atomic-audit").expect("role name"),
                    "never-store-this-display-secret",
                )
                .expect("command"),
            )
            .await?;
        assert!(matches!(applied, ManagementMutationOutcome::Applied(_)));
        let audit: (String, String, String, String, Option<String>) = sqlx::query_as(
            r"
            SELECT action,outcome,resource_kind,resource_id,request_id
            FROM security_audit_events WHERE request_id='audit-success'
            ",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(audit.0, "rbac.role.create");
        assert_eq!(audit.1, "succeeded");
        assert_eq!(audit.2, "rbac_role");
        assert_eq!(audit.3, role_id.hyphenated().to_string());
        assert_eq!(audit.4.as_deref(), Some("audit-success"));
        assert!(!format!("{audit:?}").contains("never-store-this"));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn successful_security_mutations_bump_revisions_and_conflicts_do_not_write() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let target = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        seed_member(pool, "tenant-a", manager, "351", "manager").await?;
        seed_member(pool, "tenant-a", target, "352", "target").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000025");
        let target_role = uuid("10000000-0000-4000-8000-000000000026");
        let extra_role = uuid("10000000-0000-4000-8000-000000000027");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "manager",
            false,
            &[
                permissions::ROLES_MANAGE,
                permissions::MEMBERS_MANAGE,
                permissions::ROLE_BINDINGS_MANAGE,
            ],
        )
        .await?;
        seed_role(
            pool,
            "tenant-a",
            target_role,
            "target-reader",
            false,
            &["runs:read"],
        )
        .await?;
        seed_role(pool, "tenant-a", extra_role, "extra-reader", false, &[]).await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000025"),
            manager,
            manager_role,
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000026"),
            target,
            target_role,
        )
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000025");
        let current_revision = seed_session(pool, "tenant-a", manager, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let target_authorization_before = authorization_revision(pool, "tenant-a", target).await?;

        let permission_update = repository
            .set_role_permission(SetRolePermission::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "permission-add",
                ),
                role(target_role),
                revision(1),
                Permission::new("jobs:read").expect("permission"),
                true,
            ))
            .await?;
        let updated_role = match permission_update {
            ManagementMutationOutcome::Applied(role) => role,
            outcome => panic!("unexpected permission outcome: {outcome:?}"),
        };
        assert_eq!(updated_role.revision(), revision(2));
        assert!(
            updated_role
                .permissions()
                .contains(&Permission::new("jobs:read").expect("permission"))
        );
        assert_eq!(
            authorization_revision(pool, "tenant-a", target).await?,
            target_authorization_before + 1
        );

        let conflict = repository
            .update_role(UpdateRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "role-conflict",
                ),
                role(target_role),
                revision(1),
                "Stale update",
            )?)
            .await?;
        assert!(matches!(
            conflict,
            ManagementMutationOutcome::RevisionConflict { current } if current == revision(2)
        ));

        let new_binding_id = uuid("20000000-0000-4000-8000-000000000027");
        let authorization_before_grant = authorization_revision(pool, "tenant-a", target).await?;
        let granted = repository
            .grant_role(automata_ci_auth::management::GrantRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "binding-grant",
                ),
                binding(new_binding_id),
                managed_principal(target),
                role(extra_role),
                AuthorizationScope::tenant(tenant("tenant-a")),
                None,
            )?)
            .await?;
        assert!(matches!(granted, ManagementMutationOutcome::Applied(_)));
        assert_eq!(
            authorization_revision(pool, "tenant-a", target).await?,
            authorization_before_grant + 1
        );

        let authorization_before_revoke = authorization_revision(pool, "tenant-a", target).await?;
        let revoked = repository
            .revoke_role(RevokeRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "binding-revoke",
                ),
                binding(new_binding_id),
                revision(1),
                "never-store-this-revocation-secret",
            )?)
            .await?;
        let revoked_binding = match revoked {
            ManagementMutationOutcome::Applied(binding) => binding,
            outcome => panic!("unexpected revoke outcome: {outcome:?}"),
        };
        assert_eq!(revoked_binding.revision(), revision(2));
        assert_eq!(
            authorization_revision(pool, "tenant-a", target).await?,
            authorization_before_revoke + 1
        );

        let member_revision_before = membership_revision(pool, "tenant-a", target).await?;
        let authorization_before_suspend = authorization_revision(pool, "tenant-a", target).await?;
        let suspended = repository
            .change_member_status(ChangeMemberStatus::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "member-suspend",
                ),
                managed_principal(target),
                revision(member_revision_before),
                MemberStatus::Suspended,
                Some("policy suspension".to_owned()),
            )?)
            .await?;
        let member = match suspended {
            ManagementMutationOutcome::Applied(member) => member,
            outcome => panic!("unexpected suspend outcome: {outcome:?}"),
        };
        assert_eq!(member.revision(), revision(member_revision_before + 1));
        assert_eq!(
            member.authorization_revision(),
            revision(authorization_before_suspend + 1)
        );

        for request_id in [
            "permission-add",
            "role-conflict",
            "binding-grant",
            "binding-revoke",
            "member-suspend",
        ] {
            assert_eq!(audit_count(pool, request_id).await?, 1);
        }
        let audit_text: String = sqlx::query_scalar(
            r"
            SELECT string_agg(
                action || ':' || outcome || ':' || resource_kind || ':' ||
                COALESCE(resource_id,'') || ':' || COALESCE(request_id,''),
                ',' ORDER BY sequence
            )
            FROM security_audit_events
            WHERE request_id IN (
                'permission-add','role-conflict','binding-grant',
                'binding-revoke','member-suspend'
            )
            ",
        )
        .fetch_one(pool)
        .await?;
        assert!(!audit_text.contains("never-store-this"));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn exhausted_target_revisions_fail_closed_without_blocking_role_deletion() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa41");
        let target = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbb41");
        seed_member(pool, "tenant-a", manager, "451", "manager").await?;
        seed_member(pool, "tenant-a", target, "452", "target").await?;

        let manager_role = uuid("10000000-0000-4000-8000-000000000041");
        let target_role = uuid("10000000-0000-4000-8000-000000000042");
        let deletable_role = uuid("10000000-0000-4000-8000-000000000043");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "manager",
            false,
            &[
                permissions::ROLES_MANAGE,
                permissions::MEMBERS_MANAGE,
                permissions::ROLE_BINDINGS_MANAGE,
            ],
        )
        .await?;
        seed_role(
            pool,
            "tenant-a",
            target_role,
            "target-exhausted",
            false,
            &[],
        )
        .await?;
        seed_role(
            pool,
            "tenant-a",
            deletable_role,
            "deletable-exhausted",
            false,
            &[],
        )
        .await?;

        let manager_binding = uuid("20000000-0000-4000-8000-000000000041");
        let target_binding = uuid("20000000-0000-4000-8000-000000000042");
        seed_binding(
            pool,
            "tenant-a",
            manager_binding,
            manager,
            manager_role,
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            target_binding,
            target,
            target_role,
        )
        .await?;

        sqlx::query(
            "UPDATE rbac_roles SET revision=$4 WHERE tenant_id=$1 AND id IN ($2,$3)",
        )
        .bind("tenant-a")
        .bind(target_role)
        .bind(deletable_role)
        .bind(i64::MAX)
        .execute(pool)
        .await?;
        sqlx::query(
            "UPDATE rbac_role_bindings SET revision=$3 WHERE tenant_id=$1 AND id=$2",
        )
        .bind("tenant-a")
        .bind(target_binding)
        .bind(i64::MAX)
        .execute(pool)
        .await?;
        sqlx::query(
            "UPDATE tenant_human_memberships SET revision=$3 WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind("tenant-a")
        .bind(target)
        .bind(i64::MAX)
        .execute(pool)
        .await?;

        let session_id = uuid("30000000-0000-4000-8000-000000000041");
        let current_revision = seed_session(pool, "tenant-a", manager, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let maximum_revision = revision(i64::MAX);
        let target_authorization_before =
            authorization_revision(pool, "tenant-a", target).await?;

        assert_eq!(
            repository
                .update_role(UpdateRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "exhausted-role-update",
                    ),
                    role(target_role),
                    maximum_revision,
                    "Changed despite exhaustion",
                )?)
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );
        assert_eq!(
            repository
                .set_role_permission(SetRolePermission::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "exhausted-permission-update",
                    ),
                    role(target_role),
                    maximum_revision,
                    Permission::new("jobs:read")?,
                    true,
                ))
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );
        assert_eq!(
            repository
                .revoke_role(RevokeRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "exhausted-binding-revoke",
                    ),
                    binding(target_binding),
                    maximum_revision,
                    "must not be stored",
                )?)
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );
        assert_eq!(
            repository
                .change_member_status(ChangeMemberStatus::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        "exhausted-member-suspend",
                    ),
                    managed_principal(target),
                    maximum_revision,
                    MemberStatus::Suspended,
                    Some("must not be stored".to_owned()),
                )?)
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );

        let deleted = repository
            .delete_role(DeleteRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "exhausted-role-delete",
                ),
                role(deletable_role),
                maximum_revision,
            ))
            .await?;
        assert_eq!(deleted, ManagementMutationOutcome::Applied(()));

        let role_state: (String, i64) = sqlx::query_as(
            "SELECT display_name,revision FROM rbac_roles WHERE tenant_id=$1 AND id=$2",
        )
        .bind("tenant-a")
        .bind(target_role)
        .fetch_one(pool)
        .await?;
        assert_eq!(role_state, ("target-exhausted".to_owned(), i64::MAX));
        let permission_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM rbac_role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_name='jobs:read')",
        )
        .bind("tenant-a")
        .bind(target_role)
        .fetch_one(pool)
        .await?;
        assert!(!permission_exists);
        let binding_state: (String, i64, Option<String>) = sqlx::query_as(
            "SELECT status,revision,revocation_reason FROM rbac_role_bindings WHERE tenant_id=$1 AND id=$2",
        )
        .bind("tenant-a")
        .bind(target_binding)
        .fetch_one(pool)
        .await?;
        assert_eq!(binding_state, ("active".to_owned(), i64::MAX, None));
        let member_state: (String, i64, Option<String>) = sqlx::query_as(
            "SELECT status,revision,suspended_reason FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind("tenant-a")
        .bind(target)
        .fetch_one(pool)
        .await?;
        assert_eq!(member_state, ("active".to_owned(), i64::MAX, None));
        assert_eq!(
            authorization_revision(pool, "tenant-a", target).await?,
            target_authorization_before
        );
        let deleted_role_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM rbac_roles WHERE tenant_id=$1 AND id=$2)",
        )
        .bind("tenant-a")
        .bind(deletable_role)
        .fetch_one(pool)
        .await?;
        assert!(!deleted_role_exists);

        for request_id in [
            "exhausted-role-update",
            "exhausted-permission-update",
            "exhausted-binding-revoke",
            "exhausted-member-suspend",
        ] {
            assert_eq!(audit_count(pool, request_id).await?, 0);
        }
        assert_eq!(audit_count(pool, "exhausted-role-delete").await?, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn concurrent_capability_removals_preserve_one_dual_manager() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager_a = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1");
        let manager_b = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2");
        let operator = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3");
        seed_member(pool, "tenant-a", manager_a, "401", "manager-a").await?;
        seed_member(pool, "tenant-a", manager_b, "402", "manager-b").await?;
        seed_member(pool, "tenant-a", operator, "403", "operator").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000031");
        let operator_role = uuid("10000000-0000-4000-8000-000000000032");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "manager",
            false,
            &[permissions::ROLES_MANAGE, permissions::MEMBERS_MANAGE],
        )
        .await?;
        seed_role(
            pool,
            "tenant-a",
            operator_role,
            "membership-operator",
            false,
            &[permissions::MEMBERS_MANAGE],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000031"),
            manager_a,
            manager_role,
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000032"),
            manager_b,
            manager_role,
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000033"),
            operator,
            operator_role,
        )
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000031");
        let operator_revision = seed_session(pool, "tenant-a", operator, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let command_a = ChangeMemberStatus::new(
            actor(
                "tenant-a",
                operator,
                session_id,
                operator_revision,
                "concurrent-a",
            ),
            managed_principal(manager_a),
            revision(membership_revision(pool, "tenant-a", manager_a).await?),
            MemberStatus::Suspended,
            Some("concurrent removal a".to_owned()),
        )?;
        let command_b = ChangeMemberStatus::new(
            actor(
                "tenant-a",
                operator,
                session_id,
                operator_revision,
                "concurrent-b",
            ),
            managed_principal(manager_b),
            revision(membership_revision(pool, "tenant-a", manager_b).await?),
            MemberStatus::Suspended,
            Some("concurrent removal b".to_owned()),
        )?;
        let (outcome_a, outcome_b) = tokio::join!(
            repository.change_member_status(command_a),
            repository.change_member_status(command_b)
        );
        let outcomes = [outcome_a?, outcome_b?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ManagementMutationOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ManagementMutationOutcome::LastManager))
                .count(),
            1
        );
        let active_dual_managers: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM tenant_human_memberships AS membership
            WHERE membership.tenant_id='tenant-a' AND membership.status='active'
              AND EXISTS (
                  SELECT 1 FROM rbac_role_bindings AS binding
                  JOIN rbac_role_permissions AS permission
                    ON permission.tenant_id=binding.tenant_id
                   AND permission.role_id=binding.role_id
                  WHERE binding.tenant_id=membership.tenant_id
                    AND binding.principal_id=membership.principal_id
                    AND binding.status='active' AND binding.scope_kind='tenant'
                    AND permission.permission_name='roles:manage'
              )
              AND EXISTS (
                  SELECT 1 FROM rbac_role_bindings AS binding
                  JOIN rbac_role_permissions AS permission
                    ON permission.tenant_id=binding.tenant_id
                   AND permission.role_id=binding.role_id
                  WHERE binding.tenant_id=membership.tenant_id
                    AND binding.principal_id=membership.principal_id
                    AND binding.status='active' AND binding.scope_kind='tenant'
                    AND permission.permission_name='members:manage'
              )
            ",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(active_dual_managers, 1);
        assert_eq!(audit_count(pool, "concurrent-a").await?, 1);
        assert_eq!(audit_count(pool, "concurrent-b").await?, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn reads_are_bounded_and_cross_tenant_targets_do_not_enumerate() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        seed_tenant(pool, "tenant-b").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let foreign_principal = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        seed_member(pool, "tenant-a", manager, "501", "manager").await?;
        seed_member(pool, "tenant-b", foreign_principal, "502", "foreign-member").await?;
        let manager_role = uuid("10000000-0000-4000-8000-000000000041");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "manager",
            false,
            &[
                permissions::ROLES_MANAGE,
                permissions::ROLE_BINDINGS_MANAGE,
                permissions::ROLES_READ,
                permissions::MEMBERS_READ,
            ],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000041"),
            manager,
            manager_role,
        )
        .await?;
        let foreign_role = uuid("10000000-0000-4000-8000-000000000042");
        seed_role(pool, "tenant-b", foreign_role, "foreign", false, &[]).await?;
        let local_role = uuid("10000000-0000-4000-8000-000000000043");
        seed_role(pool, "tenant-a", local_role, "local", false, &[]).await?;
        let foreign_repository = uuid("70000000-0000-4000-8000-000000000041");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id,tenant_id,scm_provider,provider_repository_id,owner,name,
                created_at_ms,updated_at_ms
            ) VALUES ($1,'tenant-b','github','foreign-1','foreign','repository',100000,100000)
            ",
        )
        .bind(foreign_repository)
        .execute(pool)
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000041");
        let current_revision = seed_session(pool, "tenant-a", manager, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let management_actor = actor(
            "tenant-a",
            manager,
            session_id,
            current_revision,
            "list-roles",
        );
        let first = repository
            .list_roles(&ListManagementRecords::new(
                management_actor.clone(),
                None,
                ManagementPageSize::new(1).expect("page size"),
            )?)
            .await?;
        let first = match first {
            automata_ci_auth::management::ManagementReadOutcome::Authorized(page) => page,
            outcome => panic!("unexpected list outcome: {outcome:?}"),
        };
        assert_eq!(first.items().len(), 1);
        let cursor = first.next_cursor().expect("next cursor").to_owned();
        let second = repository
            .list_roles(&ListManagementRecords::new(
                management_actor,
                Some(cursor),
                ManagementPageSize::new(100).expect("page size"),
            )?)
            .await?;
        let second = match second {
            automata_ci_auth::management::ManagementReadOutcome::Authorized(page) => page,
            outcome => panic!("unexpected list outcome: {outcome:?}"),
        };
        assert!(!second.items().is_empty());

        let foreign = repository
            .update_role(UpdateRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "foreign-target",
                ),
                role(foreign_role),
                revision(1),
                "No enumeration",
            )?)
            .await?;
        let absent = repository
            .update_role(UpdateRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "absent-target",
                ),
                role(uuid("10000000-0000-4000-8000-000000000099")),
                revision(1),
                "No enumeration",
            )?)
            .await?;
        assert!(matches!(foreign, ManagementMutationOutcome::NotFound));
        assert!(matches!(absent, ManagementMutationOutcome::NotFound));
        let foreign_member = repository
            .grant_role(GrantRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "foreign-member-target",
                ),
                binding(uuid("20000000-0000-4000-8000-000000000042")),
                managed_principal(foreign_principal),
                role(local_role),
                AuthorizationScope::tenant(tenant("tenant-a")),
                None,
            )?)
            .await?;
        assert!(matches!(
            foreign_member,
            ManagementMutationOutcome::NotFound
        ));
        let foreign_resource = repository
            .grant_role(GrantRole::new(
                actor(
                    "tenant-a",
                    manager,
                    session_id,
                    current_revision,
                    "foreign-resource-target",
                ),
                binding(uuid("20000000-0000-4000-8000-000000000043")),
                managed_principal(manager),
                role(local_role),
                AuthorizationScope::repository(RepositoryResource::new(
                    tenant("tenant-a"),
                    RepositoryResourceId::from_uuid(foreign_repository)
                        .expect("repository resource"),
                )),
                None,
            )?)
            .await?;
        assert!(matches!(
            foreign_resource,
            ManagementMutationOutcome::NotFound
        ));
        assert_eq!(audit_count(pool, "foreign-target").await?, 1);
        assert_eq!(audit_count(pool, "absent-target").await?, 1);
        assert_eq!(audit_count(pool, "foreign-member-target").await?, 1);
        assert_eq!(audit_count(pool, "foreign-resource-target").await?, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn management_details_and_joined_bindings_are_exact_and_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        seed_tenant(pool, "tenant-b").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1");
        let target = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1");
        let foreign = uuid("cccccccc-cccc-4ccc-8ccc-ccccccccccc1");
        seed_member(pool, "tenant-a", manager, "801", "manager").await?;
        seed_member(pool, "tenant-a", target, "802", "target").await?;
        seed_member(pool, "tenant-b", foreign, "803", "foreign").await?;

        let manager_role = uuid("10000000-0000-4000-8000-000000000061");
        let target_role = uuid("10000000-0000-4000-8000-000000000062");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "read-manager",
            false,
            &[permissions::MEMBERS_READ, permissions::ROLES_READ],
        )
        .await?;
        seed_role(
            pool,
            "tenant-a",
            target_role,
            "project-reader",
            false,
            &["runs:read"],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000061"),
            manager,
            manager_role,
        )
        .await?;

        let repository_id = uuid("70000000-0000-4000-8000-000000000061");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id,tenant_id,scm_provider,provider_repository_id,owner,name,
                created_at_ms,updated_at_ms
            ) VALUES ($1,'tenant-a','github','repository-61','acme','widgets',100000,100000)
            ",
        )
        .bind(repository_id)
        .execute(pool)
        .await?;
        let direct_binding_id = uuid("20000000-0000-4000-8000-000000000062");
        sqlx::query(
            r"
            INSERT INTO rbac_role_bindings (
                tenant_id,id,principal_id,role_id,scope_kind,repository_id,
                assignment_source,status,created_at_ms
            ) VALUES ('tenant-a',$1,$2,$3,'repository',$4,'recovery','active',100000)
            ",
        )
        .bind(direct_binding_id)
        .bind(target)
        .bind(target_role)
        .bind(repository_id)
        .execute(pool)
        .await?;

        let old_mapping = uuid("50000000-0000-4000-8000-000000000061");
        let current_mapping = uuid("50000000-0000-4000-8000-000000000062");
        for (mapping_id, organization_id) in [(old_mapping, 7601_i64), (current_mapping, 7602)] {
            sqlx::query(
                r"
                INSERT INTO github_role_mappings (
                    tenant_id,id,organization_id,organization_login,role_id,
                    scope_kind,status,created_at_ms,updated_at_ms
                ) VALUES ('tenant-a',$1,$2,'renameable-org',$3,
                          'tenant','active',100000,100000)
                ",
            )
            .bind(mapping_id)
            .bind(organization_id)
            .bind(target_role)
            .execute(pool)
            .await?;
        }
        let old_snapshot = uuid("60000000-0000-4000-8000-000000000061");
        let current_snapshot = uuid("60000000-0000-4000-8000-000000000062");
        for (snapshot_id, observed_offset_ms, organization_id) in [
            (old_snapshot, -200_000_i64, 7601_i64),
            (current_snapshot, -100_000, 7602),
        ] {
            sqlx::query(
                r"
                INSERT INTO github_membership_snapshots (
                    tenant_id,id,principal_id,provider_id,provider_subject,
                    provider_token_version,observed_at_ms,valid_until_ms
                ) VALUES (
                    'tenant-a',$1,$2,'github','802',1,
                    floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + $3,
                    floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 100000
                )
                ",
            )
            .bind(snapshot_id)
            .bind(target)
            .bind(observed_offset_ms)
            .execute(pool)
            .await?;
            sqlx::query(
                r"
                INSERT INTO github_organization_membership_observations (
                    tenant_id,snapshot_id,organization_id,organization_login,membership_role
                ) VALUES ('tenant-a',$1,$2,'observed-rename','member')
                ",
            )
            .bind(snapshot_id)
            .bind(organization_id)
            .execute(pool)
            .await?;
        }

        let manager_session = uuid("30000000-0000-4000-8000-000000000061");
        let manager_revision = seed_session(pool, "tenant-a", manager, manager_session).await?;
        let target_session = uuid("30000000-0000-4000-8000-000000000062");
        let target_revision = seed_session(pool, "tenant-a", target, target_session).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let management_actor = actor(
            "tenant-a",
            manager,
            manager_session,
            manager_revision,
            "detail-read",
        );

        let member = repository
            .read_member_detail(&ReadMemberDetail::new(
                management_actor.clone(),
                managed_principal(target),
            ))
            .await?;
        let member = match member {
            ManagementDetailOutcome::Authorized(member) => member,
            outcome => panic!("unexpected member detail outcome: {outcome:?}"),
        };
        assert_eq!(member.provider_login(), "target");
        assert_eq!(member.display_name(), Some("target display"));

        for missing in [foreign, uuid("dddddddd-dddd-4ddd-8ddd-ddddddddddd1")] {
            assert_eq!(
                repository
                    .read_member_detail(&ReadMemberDetail::new(
                        management_actor.clone(),
                        managed_principal(missing),
                    ))
                    .await?,
                ManagementDetailOutcome::NotFound
            );
        }

        let role_detail = repository
            .read_role_detail(&ReadRoleDetail::new(
                management_actor.clone(),
                role(target_role),
            ))
            .await?;
        let role_detail = match role_detail {
            ManagementDetailOutcome::Authorized(role) => role,
            outcome => panic!("unexpected role detail outcome: {outcome:?}"),
        };
        let catalog_count: i64 = sqlx::query_scalar("SELECT count(*) FROM rbac_permissions")
            .fetch_one(pool)
            .await?;
        assert_eq!(
            role_detail.permission_catalog().len(),
            usize::try_from(catalog_count).expect("catalog count")
        );
        let runs = role_detail
            .permission_catalog()
            .iter()
            .find(|entry| entry.permission().as_str() == "runs:read")
            .expect("runs permission");
        assert!(runs.granted());
        assert_eq!(runs.description(), "Read workflow runs.");
        assert!(role_detail
            .permission_catalog()
            .iter()
            .any(|entry| !entry.granted()));

        let first_request = ListManagementRoleBindings::new(
            management_actor.clone(),
            None,
            ManagementPageSize::new(1)?,
            Some(managed_principal(target)),
        )?;
        let first = repository
            .list_management_role_bindings(&first_request)
            .await?;
        let first = match first {
            ManagementReadOutcome::Authorized(page) => page,
            outcome => panic!("unexpected binding list outcome: {outcome:?}"),
        };
        assert_eq!(first.items().len(), 1);
        assert_eq!(
            first.mutation_authorization_revision(),
            Some(revision(manager_revision))
        );
        let direct = &first.items()[0];
        assert_eq!(direct.id(), binding(direct_binding_id));
        assert!(matches!(
            direct.source(),
            ManagementRoleBindingSource::Direct(
                automata_ci_auth::management::DirectRoleBindingSource::Recovery
            )
        ));
        assert_eq!(direct.role().name().as_str(), "project-reader");
        assert_eq!(direct.scope().display_name(), "acme/widgets");
        let cursor = first.next_cursor().expect("provider continuation").to_owned();
        assert_eq!(cursor, format!("d:{direct_binding_id}"));

        let second_request = ListManagementRoleBindings::new(
            management_actor.clone(),
            Some(cursor.as_str()),
            ManagementPageSize::new(10)?,
            Some(managed_principal(target)),
        )?;
        let second = repository
            .list_management_role_bindings(&second_request)
            .await?;
        let second = match second {
            ManagementReadOutcome::Authorized(page) => page,
            outcome => panic!("unexpected provider list outcome: {outcome:?}"),
        };
        assert_eq!(second.items().len(), 1);
        assert!(second.next_cursor().is_none());
        let observed = &second.items()[0];
        assert_eq!(
            observed.id(),
            RoleBindingId::for_provider_observation(
                managed_principal(target),
                ProviderRoleMappingId::from_uuid(current_mapping)?,
            )
        );
        assert!(matches!(
            observed.source(),
            ManagementRoleBindingSource::ProviderObserved { mapping_id }
                if mapping_id == ProviderRoleMappingId::from_uuid(current_mapping)?
        ));
        assert_eq!(observed.scope().display_name(), "tenant-a");
        let expected_valid_until_ms: i64 = sqlx::query_scalar(
            "SELECT valid_until_ms FROM github_membership_snapshots WHERE tenant_id='tenant-a' AND id=$1",
        )
        .bind(current_snapshot)
        .fetch_one(pool)
        .await?;
        assert_eq!(
            observed.valid_until(),
            Some(UnixTimestamp::from_seconds(u64::try_from(
                expected_valid_until_ms / 1000
            )?))
        );

        let forbidden = repository
            .read_role_detail(&ReadRoleDetail::new(
                actor(
                    "tenant-a",
                    target,
                    target_session,
                    target_revision,
                    "forbidden-detail",
                ),
                role(target_role),
            ))
            .await?;
        assert!(matches!(forbidden, ManagementDetailOutcome::Forbidden));

        let ambiguous_snapshot = uuid("60000000-0000-4000-8000-000000000063");
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','802',1,
                (SELECT observed_at_ms FROM github_membership_snapshots
                 WHERE tenant_id='tenant-a' AND id=$3),
                (SELECT valid_until_ms FROM github_membership_snapshots
                 WHERE tenant_id='tenant-a' AND id=$3)
            )
            ",
        )
        .bind(ambiguous_snapshot)
        .bind(target)
        .bind(current_snapshot)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id,snapshot_id,organization_id,organization_login,membership_role
            ) VALUES ('tenant-a',$1,7602,'ambiguous','member')
            ",
        )
        .bind(ambiguous_snapshot)
        .execute(pool)
        .await?;
        let corrupt_cursor = format!("d:{direct_binding_id}");
        let corrupt_request = ListManagementRoleBindings::new(
            management_actor.clone(),
            Some(corrupt_cursor.as_str()),
            ManagementPageSize::new(10)?,
            Some(managed_principal(target)),
        )?;
        assert_eq!(
            repository
                .list_management_role_bindings(&corrupt_request)
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );

        sqlx::query(
            "DELETE FROM rbac_role_permissions WHERE tenant_id='tenant-a' AND role_id=$1 AND permission_name=$2",
        )
        .bind(manager_role)
        .bind(permissions::MEMBERS_READ)
        .execute(pool)
        .await?;
        assert_eq!(
            repository
                .read_member_detail(&ReadMemberDetail::new(
                    management_actor,
                    managed_principal(target),
                ))
                .await?,
            ManagementDetailOutcome::SessionStale
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn mutation_readiness_is_fresh_bounded_and_authorization_first() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        seed_tenant(pool, "tenant-b").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2");
        let target = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2");
        let suspended = uuid("cccccccc-cccc-4ccc-8ccc-ccccccccccc2");
        let disabled = uuid("dddddddd-dddd-4ddd-8ddd-ddddddddddd2");
        let foreign = uuid("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2");
        seed_member(pool, "tenant-a", manager, "901", "manager").await?;
        seed_member(pool, "tenant-a", target, "902", "target").await?;
        seed_member(pool, "tenant-a", suspended, "903", "suspended").await?;
        seed_member(pool, "tenant-a", disabled, "904", "disabled").await?;
        seed_member(pool, "tenant-b", foreign, "905", "foreign").await?;
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended',revision=revision+1,updated_at_ms=200000,
                suspended_at_ms=200000,suspended_reason='test suspension'
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(suspended)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            UPDATE human_principals
            SET status='disabled',revision=revision+1,updated_at_ms=200000,
                disabled_at_ms=200000,disabled_reason='test disablement'
            WHERE id=$1
            ",
        )
        .bind(disabled)
        .execute(pool)
        .await?;

        let direct_role = uuid("10000000-0000-4000-8000-000000000071");
        let mapped_role = uuid("10000000-0000-4000-8000-000000000072");
        seed_role(
            pool,
            "tenant-a",
            direct_role,
            "option-manager",
            false,
            &[
                permissions::MEMBERS_MANAGE,
                permissions::ROLE_BINDINGS_MANAGE,
            ],
        )
        .await?;
        seed_role(
            pool,
            "tenant-a",
            mapped_role,
            "mapped-manager",
            false,
            &[permissions::ROLES_MANAGE],
        )
        .await?;
        seed_role(
            pool,
            "tenant-b",
            uuid("10000000-0000-4000-8000-000000000073"),
            "foreign-role",
            false,
            &[],
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000071"),
            manager,
            direct_role,
        )
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_role_mappings (
                tenant_id,id,organization_id,organization_login,role_id,
                scope_kind,status,created_at_ms,updated_at_ms
            ) VALUES ('tenant-a',$1,7901,'canonical-org',$2,
                      'tenant','active',100000,100000)
            ",
        )
        .bind(uuid("50000000-0000-4000-8000-000000000071"))
        .bind(mapped_role)
        .execute(pool)
        .await?;
        let snapshot = uuid("60000000-0000-4000-8000-000000000071");
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','901',1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 100000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 100000
            )
            ",
        )
        .bind(snapshot)
        .bind(manager)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id,snapshot_id,organization_id,organization_login,membership_role
            ) VALUES ('tenant-a',$1,7901,'renamed-org','member')
            ",
        )
        .bind(snapshot)
        .execute(pool)
        .await?;

        let repository_id = uuid("70000000-0000-4000-8000-000000000071");
        sqlx::query(
            r"
            INSERT INTO repositories (
                id,tenant_id,scm_provider,provider_repository_id,owner,name,
                created_at_ms,updated_at_ms
            ) VALUES ($1,'tenant-a','github','repository-71','acme','widgets',100000,100000),
                     ($2,'tenant-b','github','repository-72','foreign','private',100000,100000)
            ",
        )
        .bind(repository_id)
        .bind(uuid("70000000-0000-4000-8000-000000000072"))
        .execute(pool)
        .await?;
        let runner_group_id = uuid("80000000-0000-4000-8000-000000000071");
        sqlx::query(
            r"
            INSERT INTO runner_groups (
                id,tenant_id,name,normalized_name,created_at_ms,updated_at_ms
            ) VALUES ($1,'tenant-a','Trusted Linux','trusted-linux',100000,100000),
                     ($2,'tenant-b','Foreign group','foreign-group',100000,100000)
            ",
        )
        .bind(runner_group_id)
        .bind(uuid("80000000-0000-4000-8000-000000000072"))
        .execute(pool)
        .await?;

        let manager_session = uuid("30000000-0000-4000-8000-000000000071");
        let manager_revision = seed_session(pool, "tenant-a", manager, manager_session).await?;
        let target_session = uuid("30000000-0000-4000-8000-000000000072");
        let target_revision = seed_session(pool, "tenant-a", target, target_session).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let manager_actor = actor(
            "tenant-a",
            manager,
            manager_session,
            manager_revision,
            "mutation-readiness",
        );

        let capabilities = repository
            .read_mutation_capabilities(&ReadManagementMutationCapabilities::new(
                manager_actor.clone(),
            ))
            .await?;
        let capabilities = match capabilities {
            ManagementReadOutcome::Authorized(capabilities) => capabilities,
            outcome => panic!("unexpected capability outcome: {outcome:?}"),
        };
        assert_eq!(
            capabilities.authorization_revision(),
            revision(manager_revision)
        );
        assert!(capabilities.members_manage());
        assert!(capabilities.roles_manage());
        assert!(capabilities.role_bindings_manage());

        let options = repository
            .read_direct_binding_grant_options(&ReadDirectBindingGrantOptions::new(
                manager_actor.clone(),
            ))
            .await?;
        let options = match options {
            ManagementReadOutcome::Authorized(DirectBindingGrantOptionsState::Available(
                options,
            )) => options,
            outcome => panic!("unexpected grant-option outcome: {outcome:?}"),
        };
        assert_eq!(options.authorization_revision(), revision(manager_revision));
        assert_eq!(options.principals().len(), 2);
        assert_eq!(
            options.principals()[0].principal_id(),
            managed_principal(manager)
        );
        assert_eq!(options.principals()[0].display_name(), "manager display");
        assert_eq!(
            options.principals()[1].principal_id(),
            managed_principal(target)
        );
        assert_eq!(options.roles().len(), 2);
        assert_eq!(options.roles()[0].display_name(), "mapped-manager");
        assert_eq!(options.roles()[1].display_name(), "option-manager");
        assert_eq!(options.repositories().len(), 1);
        assert_eq!(options.repositories()[0].display_name(), "acme/widgets");
        assert_eq!(options.runner_groups().len(), 1);
        assert_eq!(options.runner_groups()[0].display_name(), "Trusted Linux");

        sqlx::query("UPDATE runner_groups SET name=E'bad\\nlabel' WHERE id=$1")
            .bind(runner_group_id)
            .execute(pool)
            .await?;
        let unauthorized_actor = actor(
            "tenant-a",
            target,
            target_session,
            target_revision,
            "unauthorized-options",
        );
        assert_eq!(
            repository
                .read_direct_binding_grant_options(&ReadDirectBindingGrantOptions::new(
                    unauthorized_actor,
                ))
                .await?,
            ManagementReadOutcome::Forbidden
        );
        assert_eq!(
            repository
                .read_direct_binding_grant_options(&ReadDirectBindingGrantOptions::new(
                    manager_actor.clone(),
                ))
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );
        sqlx::query("UPDATE runner_groups SET name='Trusted Linux' WHERE id=$1")
            .bind(runner_group_id)
            .execute(pool)
            .await?;

        sqlx::query(
            r"
            INSERT INTO runner_groups (
                id,tenant_id,name,normalized_name,created_at_ms,updated_at_ms
            )
            SELECT md5('grant-option-' || value::text)::uuid,
                   'tenant-a',
                   'generated-' || lpad(value::text,3,'0'),
                   'generated-' || lpad(value::text,3,'0'),
                   100000,100000
            FROM generate_series(1,501) AS value
            ",
        )
        .execute(pool)
        .await?;
        assert_eq!(
            repository
                .read_direct_binding_grant_options(&ReadDirectBindingGrantOptions::new(
                    manager_actor.clone(),
                ))
                .await?,
            ManagementReadOutcome::Authorized(DirectBindingGrantOptionsState::Overflow {
                authorization_revision: revision(manager_revision),
                collection: DirectBindingGrantOptionCollection::RunnerGroups,
            })
        );

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET authorization_revision=authorization_revision+1
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(manager)
        .execute(pool)
        .await?;
        assert_eq!(
            repository
                .read_mutation_capabilities(
                    &ReadManagementMutationCapabilities::new(manager_actor,)
                )
                .await?,
            ManagementReadOutcome::SessionStale
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn grant_role_rechecks_active_target_after_the_option_snapshot() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3");
        let suspended = uuid("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3");
        let disabled = uuid("cccccccc-cccc-4ccc-8ccc-ccccccccccc3");
        let changed_after_read = uuid("dddddddd-dddd-4ddd-8ddd-ddddddddddd3");
        seed_member(pool, "tenant-a", manager, "911", "manager-race").await?;
        seed_member(pool, "tenant-a", suspended, "912", "suspended-race").await?;
        seed_member(pool, "tenant-a", disabled, "913", "disabled-race").await?;
        seed_member(
            pool,
            "tenant-a",
            changed_after_read,
            "914",
            "changed-after-read",
        )
        .await?;
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended',revision=revision+1,updated_at_ms=200000,
                suspended_at_ms=200000,suspended_reason='already suspended'
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(suspended)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            UPDATE human_principals
            SET status='disabled',revision=revision+1,updated_at_ms=200000,
                disabled_at_ms=200000,disabled_reason='already disabled'
            WHERE id=$1
            ",
        )
        .bind(disabled)
        .execute(pool)
        .await?;

        let manager_role = uuid("10000000-0000-4000-8000-000000000081");
        let target_role = uuid("10000000-0000-4000-8000-000000000082");
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "grant-manager",
            false,
            &[permissions::ROLE_BINDINGS_MANAGE],
        )
        .await?;
        seed_role(pool, "tenant-a", target_role, "grant-target", false, &[]).await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid("20000000-0000-4000-8000-000000000081"),
            manager,
            manager_role,
        )
        .await?;
        let session_id = uuid("30000000-0000-4000-8000-000000000081");
        let current_revision = seed_session(pool, "tenant-a", manager, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let management_actor = actor(
            "tenant-a",
            manager,
            session_id,
            current_revision,
            "grant-options-before-race",
        );
        let options = repository
            .read_direct_binding_grant_options(&ReadDirectBindingGrantOptions::new(
                management_actor,
            ))
            .await?;
        let ManagementReadOutcome::Authorized(DirectBindingGrantOptionsState::Available(options)) =
            options
        else {
            panic!("active target options must be available before the status change");
        };
        assert!(
            options
                .principals()
                .iter()
                .any(|option| option.principal_id() == managed_principal(changed_after_read))
        );
        assert!(
            options
                .principals()
                .iter()
                .all(|option| option.principal_id() != managed_principal(suspended))
        );
        assert!(
            options
                .principals()
                .iter()
                .all(|option| option.principal_id() != managed_principal(disabled))
        );

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended',revision=revision+1,updated_at_ms=300000,
                suspended_at_ms=300000,suspended_reason='changed after option read'
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(changed_after_read)
        .execute(pool)
        .await?;

        let rejected = [
            (
                suspended,
                uuid("20000000-0000-4000-8000-000000000082"),
                "grant-suspended-target",
            ),
            (
                disabled,
                uuid("20000000-0000-4000-8000-000000000083"),
                "grant-disabled-target",
            ),
            (
                changed_after_read,
                uuid("20000000-0000-4000-8000-000000000084"),
                "grant-changed-target",
            ),
        ];
        for (principal_id, binding_id, request_id) in rejected {
            let outcome = repository
                .grant_role(GrantRole::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_id,
                        current_revision,
                        request_id,
                    ),
                    binding(binding_id),
                    managed_principal(principal_id),
                    role(target_role),
                    AuthorizationScope::tenant(tenant("tenant-a")),
                    None,
                )?)
                .await?;
            assert!(matches!(outcome, ManagementMutationOutcome::NotFound));
            assert_eq!(audit_count(pool, request_id).await?, 1);
        }
        let inserted: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM rbac_role_bindings
            WHERE tenant_id='tenant-a'
              AND id IN ($1,$2,$3)
            ",
        )
        .bind(rejected[0].1)
        .bind(rejected[1].1)
        .bind(rejected[2].1)
        .fetch_one(pool)
        .await?;
        assert_eq!(inserted, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(
    clippy::too_many_lines,
    reason = "the integration test keeps issuance, concurrent consumption, and durable assertions contiguous"
)]
async fn runner_enrollment_is_authorized_scoped_atomic_and_one_use() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        seed_tenant(pool, "runner-enrollment").await?;
        let manager = Uuid::new_v4();
        seed_member(pool, "runner-enrollment", manager, "runner-manager", "runner-manager")
            .await?;
        let role_id = Uuid::new_v4();
        seed_role(
            pool,
            "runner-enrollment",
            role_id,
            "runner-enroller",
            false,
            &["runners:enroll"],
        )
        .await?;
        seed_binding(
            pool,
            "runner-enrollment",
            Uuid::new_v4(),
            manager,
            role_id,
        )
        .await?;
        let session_id = Uuid::new_v4();
        let authority_revision =
            seed_session(pool, "runner-enrollment", manager, session_id).await?;
        let repository = PostgresHumanRbacManagementRepository::new(pool.clone());
        let token_sha256 = [7_u8; 32];
        let enrollment_id = Uuid::new_v4();
        let issued = repository
            .create_runner_enrollment_token(CreateRunnerEnrollmentToken {
                actor: actor(
                    "runner-enrollment",
                    manager,
                    session_id,
                    authority_revision,
                    "issue-runner-token",
                ),
                enrollment_id,
                token_sha256,
                runner_group: "trusted-linux".to_owned(),
                lifetime_ms: 60_000,
            })
            .await?;
        let ManagementMutationOutcome::Applied(issued) = issued else {
            return Err("runner token was not issued".into());
        };
        let retried = repository
            .create_runner_enrollment_token(CreateRunnerEnrollmentToken {
                actor: actor(
                    "runner-enrollment",
                    manager,
                    session_id,
                    authority_revision,
                    "retry-runner-token",
                ),
                enrollment_id,
                token_sha256,
                runner_group: "trusted-linux".to_owned(),
                lifetime_ms: 60_000,
            })
            .await?;
        let ManagementMutationOutcome::Applied(retried) = retried else {
            return Err("identical runner-token retry was not applied".into());
        };
        assert_eq!(retried, issued);
        let successful_create_audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security_audit_events WHERE action='runner.enrollment_token.create' AND resource_id=$1 AND outcome='succeeded'",
        )
        .bind(enrollment_id.hyphenated().to_string())
        .fetch_one(pool)
        .await?;
        assert_eq!(successful_create_audits, 1);
        let conflicting = repository
            .create_runner_enrollment_token(CreateRunnerEnrollmentToken {
                actor: actor(
                    "runner-enrollment",
                    manager,
                    session_id,
                    authority_revision,
                    "conflicting-runner-token",
                ),
                enrollment_id,
                token_sha256: [6_u8; 32],
                runner_group: "trusted-linux".to_owned(),
                lifetime_ms: 60_000,
            })
            .await?;
        assert!(matches!(
            conflicting,
            ManagementMutationOutcome::AlreadyExists
        ));
        let racing_token_sha256 = [18_u8; 32];
        let left_enrollment_id = Uuid::new_v4();
        let right_enrollment_id = Uuid::new_v4();
        let (left, right) = tokio::join!(
            repository.create_runner_enrollment_token(CreateRunnerEnrollmentToken {
                actor: actor(
                    "runner-enrollment",
                    manager,
                    session_id,
                    authority_revision,
                    "racing-runner-token-left",
                ),
                enrollment_id: left_enrollment_id,
                token_sha256: racing_token_sha256,
                runner_group: "race-left".to_owned(),
                lifetime_ms: 60_000,
            }),
            repository.create_runner_enrollment_token(CreateRunnerEnrollmentToken {
                actor: actor(
                    "runner-enrollment",
                    manager,
                    session_id,
                    authority_revision,
                    "racing-runner-token-right",
                ),
                enrollment_id: right_enrollment_id,
                token_sha256: racing_token_sha256,
                runner_group: "race-right".to_owned(),
                lifetime_ms: 60_000,
            }),
        );
        let racing_outcomes = [left?, right?];
        assert_eq!(
            racing_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ManagementMutationOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            racing_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ManagementMutationOutcome::AlreadyExists))
                .count(),
            1
        );
        let racing_state: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM runner_enrollment_tokens WHERE token_sha256=$1),(SELECT count(*) FROM runner_groups WHERE tenant_id='runner-enrollment' AND name IN ('race-left','race-right'))",
        )
        .bind(racing_token_sha256.as_slice())
        .fetch_one(pool)
        .await?;
        assert_eq!(racing_state, (1, 1));
        let first_operation_id = Uuid::new_v4();
        let second_operation_id = Uuid::new_v4();
        let first_request_sha256 = [10_u8; 32];
        let second_request_sha256 = [11_u8; 32];
        assert!(matches!(
            repository
                .prepare_runner_enrollment(PrepareRunnerEnrollment {
                    token_sha256,
                    operation_id: first_operation_id,
                    request_sha256: first_request_sha256,
                })
                .await?,
            RunnerEnrollmentPrepareOutcome::Prepared(scope)
                if scope.enrollment_id == enrollment_id
                    && scope.runner_group == "trusted-linux"
                    && scope.database_time_ms > 0
        ));

        let group = RunnerGroup::new("trusted-linux")?;
        let label = RunnerLabel::new("linux")?;
        let certificate_issued_at_seconds: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT",
        )
        .fetch_one(pool)
        .await?;
        let consume = |operation_id: Uuid,
                       request_sha256: [u8; 32],
                       response: &[u8],
                       runner_id: RunnerId,
                       name: &str,
                       certificate_byte: u8| {
            let capabilities = RunnerCapabilities::new(
                runner_id,
                RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
            )
            .with_groups([group.clone()])
            .with_labels([label.clone()])
            .with_max_parallel_jobs(2)
            .expect("valid slots");
            ConsumeRunnerEnrollment {
                token_sha256,
                operation_id,
                request_sha256,
                runner_id: runner_id.as_uuid(),
                runner_name: name.to_owned(),
                capabilities,
                certificate_leaf_sha256: [certificate_byte; 32],
                certificate_issued_at_seconds,
                certificate_expires_at_seconds: certificate_issued_at_seconds
                    + MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
                response: response.to_vec(),
            }
        };
        let extra_group_runner = RunnerId::new();
        let extra_group_capabilities = RunnerCapabilities::new(
            extra_group_runner,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_groups([group.clone(), RunnerGroup::new("unrelated-group")?])
        .with_labels([label.clone()])
        .with_max_parallel_jobs(2)?;
        assert_eq!(
            repository
                .consume_runner_enrollment(ConsumeRunnerEnrollment {
                    token_sha256,
                    operation_id: Uuid::new_v4(),
                    request_sha256: [16_u8; 32],
                    runner_id: extra_group_runner.as_uuid(),
                    runner_name: "runner-with-extra-group".to_owned(),
                    capabilities: extra_group_capabilities,
                    certificate_leaf_sha256: [17_u8; 32],
                    certificate_issued_at_seconds,
                    certificate_expires_at_seconds: certificate_issued_at_seconds
                        + MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
                    response: br#"{"runner":"extra-group"}"#.to_vec(),
                })
                .await?,
            RunnerEnrollmentConsumeOutcome::Rejected
        );
        let rejected_state: (i64, i64, bool) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM runners),(SELECT count(*) FROM runner_machine_certificates),redeem_response IS NULL FROM runner_enrollment_tokens WHERE id=$1",
        )
        .bind(enrollment_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(rejected_state, (0, 0, true));
        let first_response = br#"{"runner":"one"}"#;
        let second_response = br#"{"runner":"two"}"#;
        let first_runner = RunnerId::new();
        let second_runner = RunnerId::new();
        let (first, second) = tokio::join!(
            repository.consume_runner_enrollment(consume(
                first_operation_id,
                first_request_sha256,
                first_response,
                first_runner,
                "runner-one",
                8,
            )),
            repository.consume_runner_enrollment(consume(
                second_operation_id,
                second_request_sha256,
                second_response,
                second_runner,
                "runner-two",
                9,
            ))
        );
        let outcomes = [first?, second?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, RunnerEnrollmentConsumeOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, RunnerEnrollmentConsumeOutcome::Rejected))
                .count(),
            1
        );
        assert!(matches!(
            repository
                .prepare_runner_enrollment(PrepareRunnerEnrollment {
                    token_sha256,
                    operation_id: Uuid::new_v4(),
                    request_sha256: [12_u8; 32],
                })
                .await?,
            RunnerEnrollmentPrepareOutcome::Rejected
        ));
        let replay = if matches!(outcomes[0], RunnerEnrollmentConsumeOutcome::Applied(_)) {
            (
                first_operation_id,
                first_request_sha256,
                first_response.as_slice(),
                first_runner,
                8_u8,
            )
        } else {
            (
                second_operation_id,
                second_request_sha256,
                second_response.as_slice(),
                second_runner,
                9_u8,
            )
        };
        assert_eq!(
            repository
                .prepare_runner_enrollment(PrepareRunnerEnrollment {
                    token_sha256,
                    operation_id: replay.0,
                    request_sha256: replay.1,
                })
                .await?,
            RunnerEnrollmentPrepareOutcome::Replayed(replay.2.to_vec())
        );
        let machine = PostgresRunnerMachineDirectory::new(pool.clone())
            .find_by_leaf_sha256(Sha256Digest::from_bytes([replay.4; 32]))
            .await?
            .ok_or("enrolled runner certificate did not resolve through machine authority")?;
        assert_eq!(machine.runner_id(), replay.3);
        assert_eq!(
            machine.external_identity().as_str(),
            format!("automata:runner:{}", replay.3.as_uuid().hyphenated())
        );
        let counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM runners),(SELECT count(*) FROM runner_machine_certificates),(SELECT count(*) FROM security_audit_events WHERE action='runner.enroll')",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(counts, (1, 1, 1));

        let short_lived_token = [19_u8; 32];
        let short_lived_enrollment_id = Uuid::new_v4();
        let ManagementMutationOutcome::Applied(_) = repository
            .create_runner_enrollment_token(CreateRunnerEnrollmentToken {
                actor: actor(
                    "runner-enrollment",
                    manager,
                    session_id,
                    authority_revision,
                    "issue-short-lived-certificate-token",
                ),
                enrollment_id: short_lived_enrollment_id,
                token_sha256: short_lived_token,
                runner_group: "trusted-linux".to_owned(),
                lifetime_ms: 60_000,
            })
            .await?
        else {
            return Err("short-lived certificate token was not issued".into());
        };
        let short_lived_runner = RunnerId::new();
        let short_lived_capabilities = RunnerCapabilities::new(
            short_lived_runner,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_groups([group.clone()])
        .with_labels([label.clone()]);
        assert!(matches!(
            repository
                .consume_runner_enrollment(ConsumeRunnerEnrollment {
                    token_sha256: short_lived_token,
                    operation_id: Uuid::new_v4(),
                    request_sha256: [20_u8; 32],
                    runner_id: short_lived_runner.as_uuid(),
                    runner_name: "runner-short-lived".to_owned(),
                    capabilities: short_lived_capabilities,
                    certificate_leaf_sha256: [19_u8; 32],
                    certificate_issued_at_seconds,
                    certificate_expires_at_seconds: certificate_issued_at_seconds
                        + MIN_RUNNER_CERTIFICATE_REMAINING_LIFETIME_SECONDS
                        - 1,
                    response: br#"{"runner":"short-lived"}"#.to_vec(),
                })
                .await,
            Err(ManagementRepositoryError::InvalidRequest)
        ));
        let short_lived_state: (i64, i64, i64, bool) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM runners WHERE id=$2),(SELECT count(*) FROM runner_machine_certificates WHERE leaf_sha256=$3),(SELECT count(*) FROM security_audit_events WHERE action='runner.enroll' AND resource_id=$4),redeem_response IS NULL FROM runner_enrollment_tokens WHERE id=$1",
        )
        .bind(short_lived_enrollment_id)
        .bind(short_lived_runner.as_uuid())
        .bind([19_u8; 32].as_slice())
        .bind(short_lived_runner.as_uuid().hyphenated().to_string())
        .fetch_one(pool)
        .await?;
        assert_eq!(short_lived_state, (0, 0, 0, true));

        for index in 1..(MAX_REGISTERED_RUNNERS - 1) {
            let runner_id = RunnerId::new();
            let capabilities = RunnerCapabilities::new(
                runner_id,
                RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
            )
            .with_groups([group.clone()])
            .with_labels([label.clone()]);
            let runner_name = format!("capacity-seed-{index}");
            sqlx::query(
                r"
                INSERT INTO runners (
                    id,tenant_id,group_id,name,normalized_name,labels,capabilities,
                    slots,status,generation,created_at_ms,updated_at_ms,session_epoch,
                    external_identity,desired_state
                ) VALUES ($1,'runner-enrollment',$2,$3,$3,$4,$5,1,'offline',1,$6,$6,0,$7,'active')
                ",
            )
            .bind(runner_id.as_uuid())
            .bind(issued.runner_group_id)
            .bind(&runner_name)
            .bind(vec![label.as_str().to_owned()])
            .bind(serde_json::to_value(capabilities)?)
            .bind(certificate_issued_at_seconds * 1_000)
            .bind(format!(
                "automata:runner:{}",
                runner_id.as_uuid().hyphenated()
            ))
            .execute(pool)
            .await?;
        }
        let capacity_tokens = [[21_u8; 32], [22_u8; 32]];
        let capacity_enrollments = [Uuid::new_v4(), Uuid::new_v4()];
        for (index, (token_sha256, enrollment_id)) in capacity_tokens
            .iter()
            .zip(capacity_enrollments)
            .enumerate()
        {
            let ManagementMutationOutcome::Applied(_) = repository
                .create_runner_enrollment_token(CreateRunnerEnrollmentToken {
                    actor: actor(
                        "runner-enrollment",
                        manager,
                        session_id,
                        authority_revision,
                        if index == 0 {
                            "issue-capacity-left"
                        } else {
                            "issue-capacity-right"
                        },
                    ),
                    enrollment_id,
                    token_sha256: *token_sha256,
                    runner_group: "trusted-linux".to_owned(),
                    lifetime_ms: 60_000,
                })
                .await?
            else {
                return Err("capacity-race token was not issued".into());
            };
        }
        let capacity_runners = [RunnerId::new(), RunnerId::new()];
        let capacity_request = |index: usize| {
            let runner_id = capacity_runners[index];
            ConsumeRunnerEnrollment {
                token_sha256: capacity_tokens[index],
                operation_id: Uuid::new_v4(),
                request_sha256: [23_u8 + u8::try_from(index).expect("bounded index"); 32],
                runner_id: runner_id.as_uuid(),
                runner_name: format!("capacity-racer-{index}"),
                capabilities: RunnerCapabilities::new(
                    runner_id,
                    RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
                )
                .with_groups([group.clone()])
                .with_labels([label.clone()]),
                certificate_leaf_sha256: [25_u8 + u8::try_from(index).expect("bounded index"); 32],
                certificate_issued_at_seconds,
                certificate_expires_at_seconds: certificate_issued_at_seconds
                    + MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
                response: format!(r#"{{"runner":"capacity-racer-{index}"}}"#).into_bytes(),
            }
        };
        let (left, right) = tokio::join!(
            repository.consume_runner_enrollment(capacity_request(0)),
            repository.consume_runner_enrollment(capacity_request(1)),
        );
        let capacity_outcomes = [left?, right?];
        assert_eq!(
            capacity_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, RunnerEnrollmentConsumeOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            capacity_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, RunnerEnrollmentConsumeOutcome::CapacityExhausted))
                .count(),
            1
        );
        let loser = usize::from(!matches!(
            capacity_outcomes[0],
            RunnerEnrollmentConsumeOutcome::CapacityExhausted
        ));
        let capacity_counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM runners),(SELECT count(*) FROM runner_machine_certificates),(SELECT count(*) FROM security_audit_events WHERE action='runner.enroll')",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(
            capacity_counts,
            (i64::try_from(MAX_REGISTERED_RUNNERS)?, 2, 2)
        );
        let loser_state: (i64, i64, i64, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM runners WHERE id=$2),
                (SELECT count(*) FROM runner_machine_certificates WHERE leaf_sha256=$3),
                (SELECT count(*) FROM security_audit_events
                    WHERE action='runner.enroll' AND resource_id=$4),
                consumed_at_ms IS NULL,
                consumed_runner_id IS NULL,
                redeem_operation_id IS NULL,
                redeem_request_sha256 IS NULL,
                redeem_response IS NULL,
                redeem_certificate_expires_at_seconds IS NULL
            FROM runner_enrollment_tokens
            WHERE id=$1
            ",
        )
        .bind(capacity_enrollments[loser])
        .bind(capacity_runners[loser].as_uuid())
        .bind([25_u8 + u8::try_from(loser)?; 32].as_slice())
        .bind(
            capacity_runners[loser]
                .as_uuid()
                .hyphenated()
                .to_string(),
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(loser_state, (0, 0, 0, true, true, true, true, true, true));

        let expiring_token_sha256 = [13_u8; 32];
        let expiring_id = Uuid::new_v4();
        let expiring = repository
            .create_runner_enrollment_token(CreateRunnerEnrollmentToken {
                actor: actor(
                    "runner-enrollment",
                    manager,
                    session_id,
                    authority_revision,
                    "issue-expiring-runner-token",
                ),
                enrollment_id: expiring_id,
                token_sha256: expiring_token_sha256,
                runner_group: "trusted-linux".to_owned(),
                lifetime_ms: 60_000,
            })
            .await?;
        let ManagementMutationOutcome::Applied(expiring) = expiring else {
            return Err("expiring runner token was not issued".into());
        };
        let mut gate = pool.begin().await?;
        sqlx::query("SELECT id FROM runner_enrollment_tokens WHERE id=$1 FOR UPDATE")
            .bind(expiring_id)
            .execute(&mut *gate)
            .await?;
        let expiring_runner = RunnerId::new();
        let expiring_capabilities = RunnerCapabilities::new(
            expiring_runner,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_groups([group])
        .with_labels([label.clone()])
        .with_max_parallel_jobs(2)?;
        let certificate_issued_at_seconds = clock.now().await?.div_euclid(1_000);
        let repository_for_waiter = repository.clone();
        let waiter = tokio::spawn(async move {
            repository_for_waiter
                .consume_runner_enrollment(ConsumeRunnerEnrollment {
                    token_sha256: expiring_token_sha256,
                    operation_id: Uuid::new_v4(),
                    request_sha256: [14_u8; 32],
                    runner_id: expiring_runner.as_uuid(),
                    runner_name: "runner-after-expiry".to_owned(),
                    capabilities: expiring_capabilities,
                    certificate_leaf_sha256: [15_u8; 32],
                    certificate_issued_at_seconds,
                    certificate_expires_at_seconds: certificate_issued_at_seconds
                        + MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS,
                    response: br#"{"runner":"expired"}"#.to_vec(),
                })
                .await
        });
        if !wait_for_blocked_transaction(pool).await? {
            gate.rollback().await?;
            return Err(format!(
                "runner enrollment did not wait on its token row: {:?}",
                waiter.await?
            )
            .into());
        }
        clock.set(expiring.expires_at_ms).await?;
        gate.commit().await?;
        assert_eq!(
            waiter.await??,
            RunnerEnrollmentConsumeOutcome::Rejected
        );
        let expired_state: (i64, i64, i64, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM runners WHERE id=$2),
                (SELECT count(*) FROM runner_machine_certificates WHERE leaf_sha256=$3),
                (SELECT count(*) FROM security_audit_events
                    WHERE action='runner.enroll' AND resource_id=$4),
                consumed_at_ms IS NULL,
                consumed_runner_id IS NULL,
                redeem_operation_id IS NULL,
                redeem_request_sha256 IS NULL,
                redeem_response IS NULL,
                redeem_certificate_expires_at_seconds IS NULL
            FROM runner_enrollment_tokens
            WHERE id=$1
            ",
        )
        .bind(expiring_id)
        .bind(expiring_runner.as_uuid())
        .bind([15_u8; 32].as_slice())
        .bind(expiring_runner.as_uuid().hyphenated().to_string())
        .fetch_one(pool)
        .await?;
        assert_eq!(
            expired_state,
            (0, 0, 0, true, true, true, true, true, true)
        );
        clock
            .set(
                certificate_issued_at_seconds
                    .checked_add(MAX_RUNNER_CERTIFICATE_LIFETIME_SECONDS)
                    .and_then(|seconds| seconds.checked_mul(1_000))
                    .ok_or("certificate expiry overflow")?,
            )
            .await?;
        assert!(matches!(
            repository
                .prepare_runner_enrollment(PrepareRunnerEnrollment {
                    token_sha256,
                    operation_id: replay.0,
                    request_sha256: replay.1,
                })
                .await?,
            RunnerEnrollmentPrepareOutcome::Rejected
        ));
        Ok(())
    })
    .await
}

#[test]
fn test_permissions_are_canonical_and_unique() {
    let permissions = [
        permissions::ROLES_MANAGE,
        permissions::MEMBERS_MANAGE,
        permissions::ROLE_BINDINGS_MANAGE,
        permissions::ROLES_READ,
        permissions::MEMBERS_READ,
    ]
    .into_iter()
    .map(|permission| Permission::new(permission).expect("permission"))
    .collect::<BTreeSet<_>>();
    assert_eq!(permissions.len(), 5);
}
