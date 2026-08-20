use std::{collections::BTreeSet, time::Duration};

use automata_ci_auth::{
    authorization::Permission,
    delegated_actor::{
        DelegatedActorAssertion, DelegatedActorResolver as _, ResolveDelegatedActorOutcome,
        ResolveDelegatedActorRequest,
    },
    human::TenantId,
    time::UnixTimestamp,
};
use automata_ci_auth_postgres::PostgresDelegatedActorResolver;
use automata_ci_core::WorkspaceId;
use automata_ci_postgres::test_support::run_with_unmigrated_database;
use automata_ci_provisioning::{
    AuthorizedProvisionWorkspace, DelegatedActorIssuer, DisplayName, ExternalAccountSubject,
    OperationId, ProvisionWorkspaceCommand, ProvisioningAuthority, ProvisioningAuthorityId,
    ShardId, WorkspaceProvisioner as _,
};
use automata_ci_provisioning_postgres::PostgresWorkspaceProvisioner;
use sqlx::PgPool;
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

static MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("../automata-ci-store-postgres/migrations");

const PRE_BILLING_MIGRATION_VERSION: i64 = 62;
const PROVISIONING_PAUSE_LOCK: i64 = 1_504_061_001;

fn authority() -> ProvisioningAuthority {
    ProvisioningAuthority::new(
        ProvisioningAuthorityId::new("automata-cloud-test").expect("authority ID"),
        ShardId::new("test-shard").expect("shard ID"),
        DelegatedActorIssuer::new("https://cloud.automata.example").expect("issuer"),
    )
}

fn provision_request(workspace_id: WorkspaceId, subject: Uuid) -> AuthorizedProvisionWorkspace {
    let authority = authority();
    let command = ProvisionWorkspaceCommand::new(
        OperationId::from_uuid(Uuid::new_v4()).expect("operation ID"),
        authority.shard_id().clone(),
        workspace_id,
        DisplayName::new("Billing authorization test").expect("workspace display name"),
        authority.delegated_actor_issuer().clone(),
        ExternalAccountSubject::from_uuid(subject).expect("external subject"),
        DisplayName::new("Test Owner").expect("owner display name"),
    );
    AuthorizedProvisionWorkspace::authorize(authority, command).expect("authorized request")
}

async fn wait_for_pending_lock(pool: &PgPool, query: &'static str) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if sqlx::query_scalar::<_, bool>(query).fetch_one(pool).await? {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

async fn billing_permissions(pool: &PgPool, workspace_id: WorkspaceId) -> TestResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        r"
        SELECT permission.permission_name
        FROM rbac_roles AS role
        JOIN rbac_role_permissions AS permission
          ON permission.tenant_id = role.tenant_id
         AND permission.role_id = role.id
        WHERE role.tenant_id = $1
          AND role.name = 'workspace-owner'
          AND permission.permission_name = ANY(ARRAY['billing:manage', 'billing:read'])
        ORDER BY permission.permission_name
        ",
    )
    .bind(workspace_id.to_string())
    .fetch_all(pool)
    .await?)
}

async fn install_workspace_owner_pause(pool: &PgPool) -> TestResult {
    sqlx::raw_sql(
        r"
        CREATE FUNCTION automata_test.pause_workspace_owner_insert()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(1504061001);
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER pause_workspace_owner_insert
        AFTER INSERT ON rbac_roles
        FOR EACH ROW
        WHEN (NEW.name = 'workspace-owner')
        EXECUTE FUNCTION automata_test.pause_workspace_owner_insert();
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn billing_migration_serializes_concurrent_owner_provisioning() -> TestResult {
    run_with_unmigrated_database(
        |store| store,
        |database| async move {
            MIGRATOR
                .run_to(PRE_BILLING_MIGRATION_VERSION, database.pool())
                .await?;
            install_workspace_owner_pause(database.pool()).await?;

            let mut pause_guard = database.pool().acquire().await?;
            sqlx::query("SELECT pg_advisory_lock($1)")
                .bind(PROVISIONING_PAUSE_LOCK)
                .execute(&mut *pause_guard)
                .await?;

            let workspace_id = WorkspaceId::from_uuid(Uuid::new_v4())?;
            let subject = Uuid::new_v4();
            let adapter = PostgresWorkspaceProvisioner::new(database.pool().clone());
            let provisioning = tokio::spawn(async move {
                adapter
                    .provision(provision_request(workspace_id, subject))
                    .await
            });

            wait_for_pending_lock(
                database.pool(),
                r"
                SELECT EXISTS (
                    SELECT 1 FROM pg_locks
                    WHERE locktype = 'advisory'
                      AND database = (
                          SELECT oid FROM pg_database WHERE datname = current_database()
                      )
                      AND classid = 0
                      AND objid = 1504061001
                      AND objsubid = 1
                      AND NOT granted
                )
                ",
            )
            .await?;

            let migration_pool = database.connect_migration_pool(1).await?;
            let migration = tokio::spawn(async move { MIGRATOR.run(&migration_pool).await });
            wait_for_pending_lock(
                database.pool(),
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_locks AS lock
                    JOIN pg_class AS relation ON relation.oid = lock.relation
                    WHERE lock.database = (
                              SELECT oid FROM pg_database WHERE datname = current_database()
                          )
                      AND relation.relname = 'rbac_roles'
                      AND lock.mode = 'ShareLock'
                      AND NOT lock.granted
                )
                ",
            )
            .await?;

            let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
                .bind(PROVISIONING_PAUSE_LOCK)
                .fetch_one(&mut *pause_guard)
                .await?;
            assert!(released, "test provisioning pause lock was held");
            drop(pause_guard);

            let result = tokio::time::timeout(Duration::from_secs(10), provisioning).await???;
            tokio::time::timeout(Duration::from_secs(10), migration).await???;

            assert_eq!(
                billing_permissions(database.pool(), workspace_id).await?,
                ["billing:manage".to_owned(), "billing:read".to_owned()]
            );
            let authorization_revision: i64 = sqlx::query_scalar(
                r"
                SELECT authorization_revision
                FROM tenant_human_memberships
                WHERE tenant_id = $1 AND principal_id = $2
                ",
            )
            .bind(workspace_id.to_string())
            .bind(result.initial_owner_principal_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
            assert_eq!(authorization_revision, 4);
            Ok(())
        },
    )
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn delegated_actor_resolver_loads_exact_requested_billing_permissions() -> TestResult {
    run_with_database(|database| async move {
        let workspace_id = WorkspaceId::from_uuid(Uuid::new_v4())?;
        let subject = Uuid::new_v4();
        let provisioned = PostgresWorkspaceProvisioner::new(database.pool().clone())
            .provision(provision_request(workspace_id, subject))
            .await?;

        let tenant_id = TenantId::new(workspace_id.to_string())?;
        let assertion = DelegatedActorAssertion::new(
            "https://cloud.automata.example",
            subject,
            Uuid::new_v4(),
            Uuid::new_v4(),
            UnixTimestamp::from_seconds(10),
            UnixTimestamp::from_seconds(20),
            UnixTimestamp::from_seconds(140),
        )?;
        let billing_read = Permission::new("billing:read")?;
        let billing_manage = Permission::new("billing:manage")?;
        let ungranted = Permission::new("billing:unknown")?;
        let request = ResolveDelegatedActorRequest::new(assertion, tenant_id)
            .with_tenant_permissions(BTreeSet::from([
                billing_read.clone(),
                billing_manage.clone(),
                ungranted.clone(),
            ]))?;

        let outcome = PostgresDelegatedActorResolver::new(database.pool().clone())
            .resolve(&request)
            .await?;
        let ResolveDelegatedActorOutcome::Authenticated(snapshot) = outcome else {
            panic!("provisioned owner did not resolve as authenticated");
        };
        assert!(snapshot.allows_tenant_permission(&billing_read));
        assert!(snapshot.allows_tenant_permission(&billing_manage));
        assert!(!snapshot.allows_tenant_permission(&ungranted));
        assert_eq!(snapshot.authorization().authorization_revision(), Some(2));
        let expected_principal_id = provisioned
            .initial_owner_principal_id()
            .as_uuid()
            .hyphenated()
            .to_string();
        assert_eq!(
            snapshot
                .authorization()
                .principal_id()
                .map(automata_ci_auth::human::PrincipalId::as_str),
            Some(expected_principal_id.as_str())
        );
        assert_eq!(snapshot.viewer().display_name(), "Test Owner");
        Ok(())
    })
    .await
}
