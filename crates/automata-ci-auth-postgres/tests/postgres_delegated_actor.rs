use automata_ci_auth::{
    delegated_actor::{
        DelegatedActorAssertion, DelegatedActorResolver, ResolveDelegatedActorOutcome,
        ResolveDelegatedActorRequest,
    },
    human::TenantId,
    time::UnixTimestamp,
};
use automata_ci_auth_postgres::PostgresDelegatedActorResolver;
use sqlx::PgPool;
use uuid::Uuid;

use super::support::{TestResult, run_with_database};

const WORKSPACE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PRINCIPAL_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SUBJECT: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const ISSUER: &str = "https://cloud.automata.example";

async fn seed_delegated_actor(pool: &PgPool) -> TestResult {
    let principal = Uuid::parse_str(PRINCIPAL_ID)?;
    let subject = Uuid::parse_str(SUBJECT)?;
    let role = Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd")?;
    sqlx::query(
        "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,'Workspace A',100000,100000)",
    )
    .bind(WORKSPACE_ID)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_principals (id,status,display_name,created_at_ms,updated_at_ms)
        VALUES ($1,'active','Cloud User',100000,100000)
        ",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO delegated_actor_identities (
            issuer,subject,principal_id,display_name,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,$3,'Cloud User',100000,100000)
        ",
    )
    .bind(ISSUER)
    .bind(subject)
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id,principal_id,status,authorization_revision,created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'active',7,100000,100000)
        ",
    )
    .bind(WORKSPACE_ID)
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO rbac_roles (tenant_id,id,name,display_name,created_at_ms,updated_at_ms)
        VALUES ($1,$2,'owner','Owner',100000,100000)
        ",
    )
    .bind(WORKSPACE_ID)
    .bind(role)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id,id,principal_id,role_id,scope_kind,created_at_ms
        ) VALUES ($1,$2,$3,$4,'tenant',100000)
        ",
    )
    .bind(WORKSPACE_ID)
    .bind(Uuid::parse_str("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")?)
    .bind(principal)
    .bind(role)
    .execute(pool)
    .await?;
    Ok(())
}

fn request() -> ResolveDelegatedActorRequest {
    let assertion = DelegatedActorAssertion::new(
        ISSUER,
        Uuid::parse_str(SUBJECT).expect("subject"),
        Uuid::parse_str("ffffffff-ffff-4fff-8fff-ffffffffffff").expect("session"),
        Uuid::parse_str("12345678-1234-4234-8234-123456789abc").expect("assertion"),
        UnixTimestamp::from_seconds(900),
        UnixTimestamp::from_seconds(1_000),
        UnixTimestamp::from_seconds(1_120),
    )
    .expect("delegated assertion");
    ResolveDelegatedActorRequest::new(assertion, TenantId::new(WORKSPACE_ID).expect("workspace"))
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn resolves_current_core_membership_and_direct_rbac() -> TestResult {
    run_with_database(|database| async move {
        seed_delegated_actor(database.pool()).await?;
        let resolver = PostgresDelegatedActorResolver::new(database.pool().clone());
        let outcome = resolver.resolve(&request()).await?;
        let ResolveDelegatedActorOutcome::Authenticated(snapshot) = outcome else {
            panic!("delegated actor should resolve");
        };
        assert_eq!(snapshot.viewer().display_name(), "Cloud User");
        assert_eq!(
            snapshot
                .authorization()
                .principal_id()
                .map(automata_ci_auth::human::PrincipalId::as_str),
            Some(PRINCIPAL_ID)
        );
        assert_eq!(snapshot.authorization().authorization_revision(), Some(7));
        let grants = snapshot
            .authorization()
            .role_grants()
            .expect("authenticated grants");
        assert_eq!(grants.len(), 1);
        assert_eq!(
            grants.iter().next().map(|grant| grant.role().as_str()),
            Some("owner")
        );

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended',suspended_at_ms=updated_at_ms,suspended_reason='test'
            WHERE tenant_id=$1 AND principal_id=$2
            ",
        )
        .bind(WORKSPACE_ID)
        .bind(Uuid::parse_str(PRINCIPAL_ID)?)
        .execute(database.pool())
        .await?;
        assert!(matches!(
            resolver.resolve(&request()).await?,
            ResolveDelegatedActorOutcome::MembershipSuspended
        ));
        Ok(())
    })
    .await
}
