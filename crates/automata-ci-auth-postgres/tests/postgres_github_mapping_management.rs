mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automata_ci_auth::{
    authorization::{AuthorizationScope, RepositoryResource, RepositoryResourceId},
    github_mapping_management::{
        CreateGithubMapping, DisableGithubMapping, GithubMappingManagementRepository,
        GithubMappingMutationOutcome, GithubMappingOptionCollection, GithubMappingOptionsState,
        GithubMappingPageSize, GithubMappingReadOutcome, GithubMappingStatus, ListGithubMappings,
        ManagedGithubMappingSource, ReadGithubMappingOptions, permissions,
    },
    human::{PrincipalId, TenantId},
    management::{
        ManagementActor, ManagementRepositoryError, ManagementRequestId, ManagementRevision,
        ProviderRoleMappingId, RoleId,
    },
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_auth_postgres::PostgresGithubMappingManagementRepository;
use automata_ci_postgres_test_support::TestClock;
use sqlx::PgPool;
use uuid::Uuid;

use support::{TestResult, run_with_database};

fn uuid(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).expect("tenant")
}

fn role_id(value: Uuid) -> RoleId {
    RoleId::from_uuid(value).expect("role")
}

fn mapping_id(value: Uuid) -> ProviderRoleMappingId {
    ProviderRoleMappingId::from_uuid(value).expect("mapping")
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
    ManagementActor::new(
        tenant(tenant_id),
        PrincipalId::new(principal_id.hyphenated().to_string()).expect("principal"),
        SessionId::new(session_id.hyphenated().to_string()).expect("session"),
        revision(authorization_revision),
        Some(ManagementRequestId::new(request_id).expect("request ID")),
        UnixTimestamp::from_seconds(now),
    )
}

fn tenant_scope(tenant_id: &str) -> AuthorizationScope {
    AuthorizationScope::tenant(tenant(tenant_id))
}

fn repository_scope(tenant_id: &str, repository_id: Uuid) -> AuthorizationScope {
    AuthorizationScope::repository(RepositoryResource::new(
        tenant(tenant_id),
        RepositoryResourceId::from_uuid(repository_id).expect("repository"),
    ))
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
        INSERT INTO human_principals (id,status,display_name,created_at_ms,updated_at_ms)
        VALUES ($1,'active',$2,100000,100000)
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
    permissions: &[&str],
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id,id,name,display_name,role_kind,immutable,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,$3,$3,'custom',FALSE,100000,100000)
        ",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(name)
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
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
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
    .bind(format!("mapping-{session_id}"))
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
    .bind(format!("mapping-cli-{session_id}"))
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
async fn seed_mapping(
    pool: &PgPool,
    tenant_id: &str,
    mapping_id: Uuid,
    organization_id: i64,
    team_id: Option<i64>,
    role_id: Uuid,
    scope_kind: &str,
    repository_id: Option<Uuid>,
    runner_group_id: Option<Uuid>,
    status: &str,
    disabler: Option<Uuid>,
) -> TestResult {
    let team_slug = team_id.map(|id| format!("team-{id}"));
    let disabled_at_ms = (status == "disabled").then_some(200_000_i64);
    sqlx::query(
        r"
        INSERT INTO github_role_mappings (
            tenant_id,id,provider_id,organization_id,organization_login,
            team_id,team_slug,role_id,scope_kind,repository_id,runner_group_id,
            status,disabled_by_principal_id,created_at_ms,updated_at_ms,disabled_at_ms
        ) VALUES ($1,$2,'github',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                  100000,COALESCE($13,100000),$13)
        ",
    )
    .bind(tenant_id)
    .bind(mapping_id)
    .bind(organization_id)
    .bind(format!("org-{organization_id}"))
    .bind(team_id)
    .bind(team_slug)
    .bind(role_id)
    .bind(scope_kind)
    .bind(repository_id)
    .bind(runner_group_id)
    .bind(status)
    .bind(disabler)
    .bind(disabled_at_ms)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_repository(pool: &PgPool, tenant_id: &str, repository_id: Uuid) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO repositories (
            id,tenant_id,scm_provider,provider_repository_id,owner,name,
            created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'github',$3,'automata-ci','automata',100000,100000)
        ",
    )
    .bind(repository_id)
    .bind(tenant_id)
    .bind(repository_id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_runner_group(pool: &PgPool, tenant_id: &str, group_id: Uuid) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO runner_groups (
            id,tenant_id,name,normalized_name,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'Default runners','default-runners',100000,100000)
        ",
    )
    .bind(group_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn audit_row(
    pool: &PgPool,
    request_id: &str,
) -> TestResult<(String, String, String, String)> {
    Ok(sqlx::query_as(
        r"
        SELECT action,outcome,resource_kind,resource_id
        FROM security_audit_events WHERE request_id=$1
        ",
    )
    .bind(request_id)
    .fetch_one(pool)
    .await?)
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
#[allow(clippy::too_many_lines)]
async fn cli_actor_lifecycle_is_mapping_authority_for_reads_and_mutations() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaae1);
        seed_member(pool, "tenant-a", manager, "8101", "cli-mapping-manager").await?;
        let manager_role = uuid(0x10000000_0000_4000_8000_0000000000e1);
        let target_role = uuid(0x11000000_0000_4000_8000_0000000000e1);
        seed_role(
            pool,
            "tenant-a",
            manager_role,
            "mapping-manager",
            &[permissions::AUTH_MAPPINGS_MANAGE],
        )
        .await?;
        seed_role(pool, "tenant-a", target_role, "mapped-role", &[]).await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid(0x20000000_0000_4000_8000_0000000000e1),
            manager,
            manager_role,
        )
        .await?;

        let pending_session = uuid(0x30000000_0000_4000_8000_0000000000e1);
        let pending_revision = seed_cli_session(
            pool,
            "tenant-a",
            manager,
            pending_session,
            "pending_activation",
            false,
        )
        .await?;
        let repository = PostgresGithubMappingManagementRepository::new(pool.clone());
        assert!(matches!(
            repository
                .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                    "tenant-a",
                    manager,
                    pending_session,
                    pending_revision,
                    "pending-cli-mapping-read",
                )))
                .await?,
            GithubMappingReadOutcome::Forbidden
        ));
        assert_eq!(
            repository
                .create_mapping(CreateGithubMapping::new(
                    actor(
                        "tenant-a",
                        manager,
                        pending_session,
                        pending_revision,
                        "pending-cli-mapping-write",
                    ),
                    mapping_id(uuid(0x40000000_0000_4000_8000_0000000000e1)),
                    ManagedGithubMappingSource::organization(81, "pending-org")?,
                    role_id(target_role),
                    tenant_scope("tenant-a"),
                )?)
                .await?,
            GithubMappingMutationOutcome::Forbidden
        );

        let future_session = uuid(0x50000000_0000_4000_8000_0000000000e1);
        let future_revision =
            seed_cli_session(pool, "tenant-a", manager, future_session, "active", true).await?;
        assert_eq!(
            repository
                .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                    "tenant-a",
                    manager,
                    future_session,
                    future_revision,
                    "future-cli-mapping-read",
                )))
                .await
                .expect_err("future activation must be corrupt mapping authority"),
            ManagementRepositoryError::CorruptData
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn mutation_rechecks_expiring_permission_after_exact_target_lock_wait() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaad1);
        let target = uuid(0xbbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbd1);
        seed_member(pool, "tenant-a", manager, "701", "expiring-manager").await?;
        seed_member(pool, "tenant-a", target, "702", "lock-target").await?;
        let manage_role = uuid(0x10000000_0000_4000_8000_0000000000d1);
        let target_role = uuid(0x10000000_0000_4000_8000_0000000000d2);
        seed_role(
            pool,
            "tenant-a",
            manage_role,
            "expiring-mapping-manager",
            &[permissions::AUTH_MAPPINGS_MANAGE],
        )
        .await?;
        seed_role(pool, "tenant-a", target_role, "target", &[]).await?;
        let manager_binding = uuid(0x20000000_0000_4000_8000_0000000000d1);
        seed_binding(pool, "tenant-a", manager_binding, manager, manage_role).await?;
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
        let session_id = uuid(0x30000000_0000_4000_8000_0000000000d1);
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

        let mapping = uuid(0x60000000_0000_4000_8000_0000000000d1);
        let command = CreateGithubMapping::new(
            actor(
                "tenant-a",
                manager,
                session_id,
                manager_revision,
                "expired-mapping-permission-after-lock",
            ),
            mapping_id(mapping),
            ManagedGithubMappingSource::organization(801, "automata-ci")?,
            role_id(target_role),
            tenant_scope("tenant-a"),
        )?;
        let repository = PostgresGithubMappingManagementRepository::new(pool.clone());
        let mutation = tokio::spawn(async move { repository.create_mapping(command).await });
        if !wait_for_blocked_transaction(pool).await? {
            gate.rollback().await?;
            return Err(format!(
                "mapping mutation did not wait on the exact membership lock: {:?}",
                mutation.await?
            )
            .into());
        }
        clock.advance(2_100).await?;
        gate.commit().await?;

        assert_eq!(mutation.await??, GithubMappingMutationOutcome::Forbidden);
        let mapping_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_role_mappings WHERE tenant_id='tenant-a' AND id=$1",
        )
        .bind(mapping)
        .fetch_one(pool)
        .await?;
        assert_eq!(mapping_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn permission_split_keyset_options_create_disable_and_audit_are_closed() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        seed_tenant(pool, "tenant-b").await?;
        let reader = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaa1);
        let manager = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaa2);
        let named_admin = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaa3);
        let disabled_by_principal = reader;
        seed_member(pool, "tenant-a", reader, "101", "reader").await?;
        seed_member(pool, "tenant-a", manager, "102", "manager").await?;
        seed_member(pool, "tenant-a", named_admin, "103", "administrator").await?;

        let read_role = uuid(0x10000000_0000_4000_8000_000000000001);
        let manage_role = uuid(0x10000000_0000_4000_8000_000000000002);
        let empty_admin_role = uuid(0x10000000_0000_4000_8000_000000000003);
        let target_role = uuid(0x10000000_0000_4000_8000_000000000004);
        seed_role(
            pool,
            "tenant-a",
            read_role,
            "mapping-reader",
            &[permissions::AUTH_MAPPINGS_READ],
        )
        .await?;
        seed_role(
            pool,
            "tenant-a",
            manage_role,
            "mapping-manager",
            &[permissions::AUTH_MAPPINGS_MANAGE],
        )
        .await?;
        seed_role(pool, "tenant-a", empty_admin_role, "administrator", &[]).await?;
        seed_role(pool, "tenant-a", target_role, "target", &[]).await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid(0x20000000_0000_4000_8000_000000000001),
            reader,
            read_role,
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid(0x20000000_0000_4000_8000_000000000002),
            manager,
            manage_role,
        )
        .await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid(0x20000000_0000_4000_8000_000000000003),
            named_admin,
            empty_admin_role,
        )
        .await?;
        let repository_id = uuid(0x30000000_0000_4000_8000_000000000001);
        let runner_group_id = uuid(0x30000000_0000_4000_8000_000000000002);
        seed_repository(pool, "tenant-a", repository_id).await?;
        seed_runner_group(pool, "tenant-a", runner_group_id).await?;

        let first = uuid(0x40000000_0000_4000_8000_000000000001);
        let second = uuid(0x40000000_0000_4000_8000_000000000002);
        let third = uuid(0x40000000_0000_4000_8000_000000000003);
        seed_mapping(
            pool,
            "tenant-a",
            first,
            10,
            None,
            target_role,
            "tenant",
            None,
            None,
            "active",
            None,
        )
        .await?;
        seed_mapping(
            pool,
            "tenant-a",
            second,
            11,
            Some(12),
            target_role,
            "repository",
            Some(repository_id),
            None,
            "active",
            None,
        )
        .await?;
        seed_mapping(
            pool,
            "tenant-a",
            third,
            13,
            None,
            target_role,
            "runner_group",
            None,
            Some(runner_group_id),
            "disabled",
            Some(disabled_by_principal),
        )
        .await?;

        let reader_session = uuid(0x50000000_0000_4000_8000_000000000001);
        let manager_session = uuid(0x50000000_0000_4000_8000_000000000002);
        let named_session = uuid(0x50000000_0000_4000_8000_000000000003);
        let reader_revision = seed_session(pool, "tenant-a", reader, reader_session).await?;
        let manager_revision = seed_session(pool, "tenant-a", manager, manager_session).await?;
        let named_revision = seed_session(pool, "tenant-a", named_admin, named_session).await?;
        let repository = PostgresGithubMappingManagementRepository::new(pool.clone());

        let page_one = repository
            .list_mappings(&ListGithubMappings::new(
                actor(
                    "tenant-a",
                    reader,
                    reader_session,
                    reader_revision,
                    "list-one",
                ),
                None,
                Some(GithubMappingPageSize::new(2)?),
            )?)
            .await?;
        let GithubMappingReadOutcome::Authorized(page_one) = page_one else {
            panic!("reader must list mappings");
        };
        assert_eq!(page_one.items().len(), 2);
        assert_eq!(page_one.items()[0].mapping_id().as_uuid(), first);
        assert_eq!(page_one.items()[1].mapping_id().as_uuid(), second);
        let cursor = page_one.next_cursor().expect("next cursor").encode();
        let page_two = repository
            .list_mappings(&ListGithubMappings::new(
                actor(
                    "tenant-a",
                    reader,
                    reader_session,
                    reader_revision,
                    "list-two",
                ),
                Some(&cursor),
                Some(GithubMappingPageSize::new(2)?),
            )?)
            .await?;
        let GithubMappingReadOutcome::Authorized(page_two) = page_two else {
            panic!("second page must be authorized");
        };
        assert_eq!(page_two.items().len(), 1);
        assert_eq!(page_two.items()[0].mapping_id().as_uuid(), third);
        assert_eq!(page_two.items()[0].status(), GithubMappingStatus::Disabled);
        assert_eq!(page_two.next_cursor(), None);

        assert!(matches!(
            repository
                .list_mappings(&ListGithubMappings::new(
                    actor(
                        "tenant-a",
                        manager,
                        manager_session,
                        manager_revision,
                        "manage-cannot-list",
                    ),
                    None,
                    None,
                )?)
                .await?,
            GithubMappingReadOutcome::Forbidden
        ));
        assert!(matches!(
            repository
                .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                    "tenant-a",
                    reader,
                    reader_session,
                    reader_revision,
                    "read-cannot-manage",
                )))
                .await?,
            GithubMappingReadOutcome::Forbidden
        ));
        let options = repository
            .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                "tenant-a",
                manager,
                manager_session,
                manager_revision,
                "manage-options",
            )))
            .await?;
        let GithubMappingReadOutcome::Authorized(GithubMappingOptionsState::Available(options)) =
            options
        else {
            panic!("manager options must be complete");
        };
        assert_eq!(options.authorization_revision(), revision(manager_revision));
        assert_eq!(options.repositories().len(), 1);
        assert_eq!(options.runner_groups().len(), 1);

        let denied_id = uuid(0x60000000_0000_4000_8000_000000000001);
        let denied = repository
            .create_mapping(CreateGithubMapping::new(
                actor(
                    "tenant-a",
                    named_admin,
                    named_session,
                    named_revision,
                    "name-is-not-authority",
                ),
                mapping_id(denied_id),
                ManagedGithubMappingSource::organization(90, "private-name")?,
                role_id(target_role),
                tenant_scope("tenant-a"),
            )?)
            .await?;
        assert!(matches!(denied, GithubMappingMutationOutcome::Forbidden));
        assert_eq!(
            audit_row(pool, "name-is-not-authority").await?,
            (
                "rbac.github_mapping.create".to_owned(),
                "denied".to_owned(),
                "github_role_mapping".to_owned(),
                denied_id.to_string(),
            )
        );

        let created_id = uuid(0x60000000_0000_4000_8000_000000000002);
        let before_revisions = [
            authorization_revision(pool, "tenant-a", reader).await?,
            authorization_revision(pool, "tenant-a", manager).await?,
            authorization_revision(pool, "tenant-a", named_admin).await?,
        ];
        let created = repository
            .create_mapping(CreateGithubMapping::new(
                actor(
                    "tenant-a",
                    manager,
                    manager_session,
                    manager_revision,
                    "mapping-create",
                ),
                mapping_id(created_id),
                ManagedGithubMappingSource::team(70, "Private-Org", 71, "Private-Team")?,
                role_id(target_role),
                repository_scope("tenant-a", repository_id),
            )?)
            .await?;
        let GithubMappingMutationOutcome::Applied(created) = created else {
            panic!("mapping must be created");
        };
        assert_eq!(created.revision(), revision(1));
        assert_eq!(created.status(), GithubMappingStatus::Active);
        assert_eq!(created.source().organization_id().get(), 70);
        assert_eq!(created.source().team_id().expect("team").get(), 71);
        assert_eq!(
            audit_row(pool, "mapping-create").await?,
            (
                "rbac.github_mapping.create".to_owned(),
                "succeeded".to_owned(),
                "github_role_mapping".to_owned(),
                created_id.to_string(),
            )
        );
        for (principal_id, before) in [reader, manager, named_admin]
            .into_iter()
            .zip(before_revisions)
        {
            assert_eq!(
                authorization_revision(pool, "tenant-a", principal_id).await?,
                before + 1
            );
        }
        assert!(matches!(
            repository
                .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                    "tenant-a",
                    manager,
                    manager_session,
                    manager_revision,
                    "create-stales-session",
                )))
                .await?,
            GithubMappingReadOutcome::SessionStale
        ));

        let manager_session_two = uuid(0x50000000_0000_4000_8000_000000000012);
        let manager_revision_two =
            seed_session(pool, "tenant-a", manager, manager_session_two).await?;
        let conflict = repository
            .disable_mapping(DisableGithubMapping::new(
                actor(
                    "tenant-a",
                    manager,
                    manager_session_two,
                    manager_revision_two,
                    "disable-conflict",
                ),
                mapping_id(created_id),
                revision(2),
            ))
            .await?;
        assert!(matches!(
            conflict,
            GithubMappingMutationOutcome::RevisionConflict { current } if current == revision(1)
        ));
        let disable_outcome = repository
            .disable_mapping(DisableGithubMapping::new(
                actor(
                    "tenant-a",
                    manager,
                    manager_session_two,
                    manager_revision_two,
                    "mapping-disable",
                ),
                mapping_id(created_id),
                revision(1),
            ))
            .await?;
        let GithubMappingMutationOutcome::Applied(disabled_record) = disable_outcome else {
            panic!("mapping must be disabled");
        };
        assert_eq!(disabled_record.status(), GithubMappingStatus::Disabled);
        assert_eq!(disabled_record.revision(), revision(2));

        let manager_session_three = uuid(0x50000000_0000_4000_8000_000000000013);
        let manager_revision_three =
            seed_session(pool, "tenant-a", manager, manager_session_three).await?;
        assert!(matches!(
            repository
                .disable_mapping(DisableGithubMapping::new(
                    actor(
                        "tenant-a",
                        manager,
                        manager_session_three,
                        manager_revision_three,
                        "already-disabled",
                    ),
                    mapping_id(created_id),
                    revision(2),
                ))
                .await?,
            GithubMappingMutationOutcome::AlreadyDisabled
        ));

        let foreign_role = uuid(0x10000000_0000_4000_8000_000000000099);
        seed_role(pool, "tenant-b", foreign_role, "foreign", &[]).await?;
        let foreign_mapping = uuid(0x60000000_0000_4000_8000_000000000099);
        seed_mapping(
            pool,
            "tenant-b",
            foreign_mapping,
            99,
            None,
            foreign_role,
            "tenant",
            None,
            None,
            "active",
            None,
        )
        .await?;
        for (request_id, target) in [
            ("foreign-mapping", foreign_mapping),
            (
                "absent-mapping",
                uuid(0x60000000_0000_4000_8000_000000000098),
            ),
        ] {
            assert!(matches!(
                repository
                    .disable_mapping(DisableGithubMapping::new(
                        actor(
                            "tenant-a",
                            manager,
                            manager_session_three,
                            manager_revision_three,
                            request_id,
                        ),
                        mapping_id(target),
                        revision(1),
                    ))
                    .await?,
                GithubMappingMutationOutcome::NotFound
            ));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn create_rechecks_targets_and_duplicate_races_serialize_before_authority() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaab1);
        seed_member(pool, "tenant-a", manager, "201", "manager").await?;
        let manage_role = uuid(0x10000000_0000_4000_8000_0000000000b1);
        let target_role = uuid(0x10000000_0000_4000_8000_0000000000b2);
        seed_role(
            pool,
            "tenant-a",
            manage_role,
            "mapping-manager",
            &[permissions::AUTH_MAPPINGS_MANAGE],
        )
        .await?;
        seed_role(pool, "tenant-a", target_role, "target", &[]).await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid(0x20000000_0000_4000_8000_0000000000b1),
            manager,
            manage_role,
        )
        .await?;
        let repository_id = uuid(0x30000000_0000_4000_8000_0000000000b1);
        seed_repository(pool, "tenant-a", repository_id).await?;
        let repository = PostgresGithubMappingManagementRepository::new(pool.clone());
        let session = uuid(0x50000000_0000_4000_8000_0000000000b1);
        let current_revision = seed_session(pool, "tenant-a", manager, session).await?;

        let missing_role = uuid(0x10000000_0000_4000_8000_0000000000ff);
        assert!(matches!(
            repository
                .create_mapping(CreateGithubMapping::new(
                    actor(
                        "tenant-a",
                        manager,
                        session,
                        current_revision,
                        "missing-role",
                    ),
                    mapping_id(uuid(0x60000000_0000_4000_8000_0000000000b1)),
                    ManagedGithubMappingSource::organization(301, "automata-ci")?,
                    role_id(missing_role),
                    tenant_scope("tenant-a"),
                )?)
                .await?,
            GithubMappingMutationOutcome::NotFound
        ));
        assert!(matches!(
            repository
                .create_mapping(CreateGithubMapping::new(
                    actor(
                        "tenant-a",
                        manager,
                        session,
                        current_revision,
                        "missing-scope",
                    ),
                    mapping_id(uuid(0x60000000_0000_4000_8000_0000000000b2)),
                    ManagedGithubMappingSource::organization(302, "automata-ci")?,
                    role_id(target_role),
                    repository_scope("tenant-a", uuid(0x30000000_0000_4000_8000_0000000000ff),),
                )?)
                .await?,
            GithubMappingMutationOutcome::NotFound
        ));

        let session_two = uuid(0x50000000_0000_4000_8000_0000000000b2);
        let second_revision = seed_session(pool, "tenant-a", manager, session_two).await?;
        let first_id = uuid(0x60000000_0000_4000_8000_0000000000c1);
        let second_id = uuid(0x60000000_0000_4000_8000_0000000000c2);
        let command_one = CreateGithubMapping::new(
            actor("tenant-a", manager, session, current_revision, "race-one"),
            mapping_id(first_id),
            ManagedGithubMappingSource::team(400, "automata-ci", 401, "core")?,
            role_id(target_role),
            repository_scope("tenant-a", repository_id),
        )?;
        let command_two = CreateGithubMapping::new(
            actor(
                "tenant-a",
                manager,
                session_two,
                second_revision,
                "race-two",
            ),
            mapping_id(second_id),
            ManagedGithubMappingSource::team(400, "renamed-org", 401, "renamed-team")?,
            role_id(target_role),
            repository_scope("tenant-a", repository_id),
        )?;
        let (one, two) = tokio::join!(
            repository.create_mapping(command_one),
            repository.create_mapping(command_two)
        );
        let one = one?;
        let two = two?;
        assert!(
            matches!(one, GithubMappingMutationOutcome::Applied(_))
                ^ matches!(two, GithubMappingMutationOutcome::Applied(_))
        );
        assert!(
            matches!(one, GithubMappingMutationOutcome::SessionStale)
                ^ matches!(two, GithubMappingMutationOutcome::SessionStale)
        );
        let active_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*) FROM github_role_mappings
            WHERE tenant_id='tenant-a' AND organization_id=400 AND team_id=401
              AND role_id=$1 AND repository_id=$2 AND status='active'
            ",
        )
        .bind(target_role)
        .bind(repository_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(active_count, 1);

        let session_three = uuid(0x50000000_0000_4000_8000_0000000000b3);
        let third_revision = seed_session(pool, "tenant-a", manager, session_three).await?;
        assert!(matches!(
            repository
                .create_mapping(CreateGithubMapping::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_three,
                        third_revision,
                        "duplicate-active",
                    ),
                    mapping_id(uuid(0x60000000_0000_4000_8000_0000000000c3)),
                    ManagedGithubMappingSource::team(400, "different-name", 401, "other-name")?,
                    role_id(target_role),
                    repository_scope("tenant-a", repository_id),
                )?)
                .await?,
            GithubMappingMutationOutcome::AlreadyExists
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn newest_numeric_github_mapping_can_manage_but_names_and_old_snapshots_cannot() -> TestResult
{
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaac1);
        seed_member(pool, "tenant-a", manager, "301", "mapped-manager").await?;
        let authority_role = uuid(0x10000000_0000_4000_8000_0000000000c1);
        let target_role = uuid(0x10000000_0000_4000_8000_0000000000c2);
        seed_role(
            pool,
            "tenant-a",
            authority_role,
            "mapped-authority",
            &[permissions::AUTH_MAPPINGS_MANAGE],
        )
        .await?;
        seed_role(pool, "tenant-a", target_role, "target", &[]).await?;
        seed_mapping(
            pool,
            "tenant-a",
            uuid(0x40000000_0000_4000_8000_0000000000c1),
            7001,
            None,
            authority_role,
            "tenant",
            None,
            None,
            "active",
            None,
        )
        .await?;
        let snapshot = uuid(0x70000000_0000_4000_8000_0000000000c1);
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','301',1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 200000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 200000
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
            ) VALUES ('tenant-a',$1,7001,'completely-renamed','member')
            ",
        )
        .bind(snapshot)
        .execute(pool)
        .await?;
        let session = uuid(0x50000000_0000_4000_8000_0000000000c1);
        let current_revision = seed_session(pool, "tenant-a", manager, session).await?;
        let repository = PostgresGithubMappingManagementRepository::new(pool.clone());
        assert!(matches!(
            repository
                .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                    "tenant-a",
                    manager,
                    session,
                    current_revision,
                    "mapped-options",
                )))
                .await?,
            GithubMappingReadOutcome::Authorized(GithubMappingOptionsState::Available(_))
        ));
        assert!(matches!(
            repository
                .create_mapping(CreateGithubMapping::new(
                    actor(
                        "tenant-a",
                        manager,
                        session,
                        current_revision,
                        "mapped-create",
                    ),
                    mapping_id(uuid(0x60000000_0000_4000_8000_0000000000d1)),
                    ManagedGithubMappingSource::organization(8001, "created-by-mapping")?,
                    role_id(target_role),
                    tenant_scope("tenant-a"),
                )?)
                .await?,
            GithubMappingMutationOutcome::Applied(_)
        ));

        let newer = uuid(0x70000000_0000_4000_8000_0000000000c2);
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','301',1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 100000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 200000
            )
            ",
        )
        .bind(newer)
        .bind(manager)
        .execute(pool)
        .await?;
        let session_two = uuid(0x50000000_0000_4000_8000_0000000000c2);
        let second_revision = seed_session(pool, "tenant-a", manager, session_two).await?;
        assert!(matches!(
            repository
                .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                    "tenant-a",
                    manager,
                    session_two,
                    second_revision,
                    "newest-empty",
                )))
                .await?,
            GithubMappingReadOutcome::Forbidden
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn options_overflow_and_revision_exhaustion_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let manager = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaad1);
        seed_member(pool, "tenant-a", manager, "401", "manager").await?;
        let manage_role = uuid(0x10000000_0000_4000_8000_0000000000d1);
        let target_role = uuid(0x10000000_0000_4000_8000_0000000000d2);
        seed_role(
            pool,
            "tenant-a",
            manage_role,
            "mapping-manager",
            &[permissions::AUTH_MAPPINGS_MANAGE],
        )
        .await?;
        seed_role(pool, "tenant-a", target_role, "target", &[]).await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid(0x20000000_0000_4000_8000_0000000000d1),
            manager,
            manage_role,
        )
        .await?;
        let session = uuid(0x50000000_0000_4000_8000_0000000000d1);
        let current_revision = seed_session(pool, "tenant-a", manager, session).await?;
        let repository = PostgresGithubMappingManagementRepository::new(pool.clone());

        sqlx::query(
            r"
            INSERT INTO rbac_roles (
                tenant_id,id,name,display_name,role_kind,immutable,created_at_ms,updated_at_ms
            )
            SELECT 'tenant-a',md5('mapping-role-' || value::text)::uuid,
                   'mapping-option-' || value::text,
                   'Mapping option ' || lpad(value::text,3,'0'),
                   'custom',FALSE,100000,100000
            FROM generate_series(1,499) AS value
            ",
        )
        .execute(pool)
        .await?;
        let role_overflow = repository
            .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                "tenant-a",
                manager,
                session,
                current_revision,
                "role-overflow",
            )))
            .await?;
        assert!(matches!(
            role_overflow,
            GithubMappingReadOutcome::Authorized(GithubMappingOptionsState::Overflow {
                collection: GithubMappingOptionCollection::Roles,
                ..
            })
        ));
        sqlx::query("DELETE FROM rbac_roles WHERE tenant_id='tenant-a' AND name LIKE 'mapping-option-%'")
            .execute(pool)
            .await?;

        sqlx::query(
            r"
            INSERT INTO repositories (
                id,tenant_id,scm_provider,provider_repository_id,owner,name,
                created_at_ms,updated_at_ms
            )
            SELECT md5('mapping-repository-' || value::text)::uuid,'tenant-a','github',
                   'option-' || value::text,'automata-ci',
                   'repository-' || lpad(value::text,3,'0'),100000,100000
            FROM generate_series(1,501) AS value
            ",
        )
        .execute(pool)
        .await?;
        assert!(matches!(
            repository
                .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                    "tenant-a",
                    manager,
                    session,
                    current_revision,
                    "repository-overflow",
                )))
                .await?,
            GithubMappingReadOutcome::Authorized(GithubMappingOptionsState::Overflow {
                collection: GithubMappingOptionCollection::Repositories,
                ..
            })
        ));
        sqlx::query("DELETE FROM repositories WHERE tenant_id='tenant-a'")
            .execute(pool)
            .await?;

        sqlx::query(
            r"
            INSERT INTO runner_groups (
                id,tenant_id,name,normalized_name,created_at_ms,updated_at_ms
            )
            SELECT md5('mapping-runner-group-' || value::text)::uuid,'tenant-a',
                   'Runner group ' || lpad(value::text,3,'0'),
                   'runner-group-' || value::text,100000,100000
            FROM generate_series(1,501) AS value
            ",
        )
        .execute(pool)
        .await?;
        assert!(matches!(
            repository
                .read_mapping_options(&ReadGithubMappingOptions::new(actor(
                    "tenant-a",
                    manager,
                    session,
                    current_revision,
                    "runner-group-overflow",
                )))
                .await?,
            GithubMappingReadOutcome::Authorized(GithubMappingOptionsState::Overflow {
                collection: GithubMappingOptionCollection::RunnerGroups,
                ..
            })
        ));

        let exhausted_mapping = uuid(0x60000000_0000_4000_8000_0000000000e1);
        seed_mapping(
            pool,
            "tenant-a",
            exhausted_mapping,
            9001,
            None,
            target_role,
            "tenant",
            None,
            None,
            "active",
            None,
        )
        .await?;
        sqlx::query(
            "UPDATE github_role_mappings SET revision=$2 WHERE tenant_id='tenant-a' AND id=$1",
        )
        .bind(exhausted_mapping)
        .bind(i64::MAX)
        .execute(pool)
        .await?;
        let session_two = uuid(0x50000000_0000_4000_8000_0000000000d2);
        let second_revision = seed_session(pool, "tenant-a", manager, session_two).await?;
        assert_eq!(
            repository
                .disable_mapping(DisableGithubMapping::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_two,
                        second_revision,
                        "mapping-revision-exhausted",
                    ),
                    mapping_id(exhausted_mapping),
                    revision(i64::MAX),
                ))
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );

        sqlx::query(
            "UPDATE tenant_human_memberships SET authorization_revision=$2 WHERE tenant_id='tenant-a' AND principal_id=$1",
        )
        .bind(manager)
        .bind(i64::MAX)
        .execute(pool)
        .await?;
        let session_three = uuid(0x50000000_0000_4000_8000_0000000000d3);
        let third_revision = seed_session(pool, "tenant-a", manager, session_three).await?;
        assert_eq!(third_revision, i64::MAX);
        assert_eq!(
            repository
                .create_mapping(CreateGithubMapping::new(
                    actor(
                        "tenant-a",
                        manager,
                        session_three,
                        third_revision,
                        "authorization-revision-exhausted",
                    ),
                    mapping_id(uuid(0x60000000_0000_4000_8000_0000000000e2)),
                    ManagedGithubMappingSource::organization(9002, "automata-ci")?,
                    role_id(target_role),
                    tenant_scope("tenant-a"),
                )?)
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn database_rejects_nonpositive_and_malformed_numeric_source_shapes() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let role = uuid(0x10000000_0000_4000_8000_0000000000e1);
        seed_role(pool, "tenant-a", role, "target", &[]).await?;
        for query in [
            r"
            INSERT INTO github_role_mappings (
                tenant_id,id,organization_id,organization_login,role_id,
                scope_kind,status,created_at_ms,updated_at_ms
            ) VALUES ('tenant-a','60000000-0000-4000-8000-0000000000f1',0,
                      'automata-ci',$1,'tenant','active',100000,100000)
            ",
            r"
            INSERT INTO github_role_mappings (
                tenant_id,id,organization_id,organization_login,team_id,team_slug,
                role_id,scope_kind,status,created_at_ms,updated_at_ms
            ) VALUES ('tenant-a','60000000-0000-4000-8000-0000000000f2',1,
                      'automata-ci',2,NULL,$1,'tenant','active',100000,100000)
            ",
            r"
            INSERT INTO github_role_mappings (
                tenant_id,id,organization_id,organization_login,role_id,
                scope_kind,status,created_at_ms,updated_at_ms
            ) VALUES ('tenant-a','60000000-0000-4000-8000-0000000000f3',1,
                      'contains space',$1,'tenant','active',100000,100000)
            ",
        ] {
            assert!(sqlx::query(query).bind(role).execute(pool).await.is_err());
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn disabled_mapping_without_exact_actor_membership_is_corrupt() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let reader = uuid(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaf1);
        seed_member(pool, "tenant-a", reader, "501", "reader").await?;
        let read_role = uuid(0x10000000_0000_4000_8000_0000000000f1);
        let target_role = uuid(0x10000000_0000_4000_8000_0000000000f2);
        seed_role(
            pool,
            "tenant-a",
            read_role,
            "mapping-reader",
            &[permissions::AUTH_MAPPINGS_READ],
        )
        .await?;
        seed_role(pool, "tenant-a", target_role, "target", &[]).await?;
        seed_binding(
            pool,
            "tenant-a",
            uuid(0x20000000_0000_4000_8000_0000000000f1),
            reader,
            read_role,
        )
        .await?;
        seed_mapping(
            pool,
            "tenant-a",
            uuid(0x60000000_0000_4000_8000_0000000000f4),
            10_001,
            None,
            target_role,
            "tenant",
            None,
            None,
            "disabled",
            None,
        )
        .await?;
        let session = uuid(0x50000000_0000_4000_8000_0000000000f1);
        let current_revision = seed_session(pool, "tenant-a", reader, session).await?;
        let repository = PostgresGithubMappingManagementRepository::new(pool.clone());
        assert_eq!(
            repository
                .list_mappings(&ListGithubMappings::new(
                    actor(
                        "tenant-a",
                        reader,
                        session,
                        current_revision,
                        "corrupt-disabled-attribution",
                    ),
                    None,
                    None,
                )?)
                .await,
            Err(ManagementRepositoryError::CorruptData)
        );
        Ok(())
    })
    .await
}
