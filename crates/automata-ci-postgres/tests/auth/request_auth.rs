use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_auth::{
    authorization::{
        AuthorizationRequest, AuthorizationScope, CompositeAuthorizationPolicy, Permission,
    },
    github::{
        GithubMembershipObservation, GithubMembershipRepository, GithubMembershipSnapshot,
        GithubMembershipSnapshotId, GithubOrganizationId, GithubOrganizationLogin,
        GithubOrganizationMembership, GithubOrganizationMembershipRole, GithubTeam, GithubTeamId,
        GithubTeamSlug, PersistGithubMembershipSnapshot, PersistGithubMembershipSnapshotOutcome,
    },
    human::{PrincipalId, ProviderSubject, TenantId},
    request_auth::{
        RequestAuthenticationResolver, RequestAuthenticationResolverError,
        ResolveAuthenticatedRequest, ResolveAuthenticatedRequestOutcome,
    },
    session::{SessionKind, SessionTokenDigest, SessionTokenDigestKeyId, SessionTokenLookup},
    time::UnixTimestamp,
    vault::TokenVersion,
};
use automata_ci_postgres::auth::{
    PostgresGithubMembershipRepository, PostgresRequestAuthenticationResolver,
};
use automata_ci_postgres_test_support::TestClock;
use sqlx::PgPool;
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

const PRINCIPAL_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SESSION_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const TEST_REFERENCE_MILLISECONDS: i64 = 150_000;

fn rebased_milliseconds(milliseconds: i64) -> i64 {
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_secs(),
    )
    .expect("test time fits i64")
    .checked_mul(1000)
    .expect("test milliseconds");
    now_ms
        .checked_add(milliseconds - TEST_REFERENCE_MILLISECONDS)
        .expect("rebased test timestamp")
}

fn lookup(byte: u8) -> SessionTokenLookup {
    SessionTokenLookup::new(
        SessionTokenDigestKeyId::new("session-hmac-v1").expect("key ID"),
        SessionTokenDigest::new([byte; 32]),
    )
}

fn request(byte: u8, kind: SessionKind, _scenario_time: u64) -> ResolveAuthenticatedRequest {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_secs();
    request_at(byte, kind, now)
}

fn request_at(byte: u8, kind: SessionKind, now_seconds: u64) -> ResolveAuthenticatedRequest {
    ResolveAuthenticatedRequest::new(lookup(byte), kind, UnixTimestamp::from_seconds(now_seconds))
}

async fn database_now_seconds(pool: &PgPool) -> TestResult<u64> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
            .fetch_one(pool)
            .await?;
    Ok(u64::try_from(now)?)
}

async fn seed_identity(pool: &PgPool) -> TestResult<Uuid> {
    let principal = Uuid::parse_str(PRINCIPAL_ID)?;
    sqlx::query(
        "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ('tenant-a','Tenant A',100000,100000)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_principals (
            id,status,display_name,created_at_ms,updated_at_ms
        ) VALUES ($1,'active','Durable Viewer',100000,100000)
        ",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id,provider_id,provider_subject,provider_login,
            normalized_login,display_name,first_authenticated_at_ms,
            last_authenticated_at_ms,last_observed_at_ms,created_at_ms,updated_at_ms
        ) VALUES ($1,'github','42','octocat','octocat','Provider Viewer',
                  100000,120000,120000,100000,120000)
        ",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id,principal_id,status,created_at_ms,updated_at_ms
        ) VALUES ('tenant-a',$1,'active',100000,100000)
        ",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    Ok(principal)
}

async fn seed_provider_token(pool: &PgPool, principal: Uuid) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO human_provider_tokens (
            envelope_record_id,tenant_id,principal_id,provider_id,provider_subject,
            version,grant_kind,token_type,scopes,
            encrypted_payload,payload_nonce,wrapped_data_key,encryption_key_id,encryption_schema,
            issued_at_ms,access_expires_at_ms,created_at_ms,updated_at_ms
        ) VALUES (
            $2,'tenant-a',$1,'github','42',7,'browser_authorization_code','bearer',
            ARRAY['read:org'],$3,$4,$5,'test-kek',1,
            floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 60000,
            floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 750000,
            floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 60000,
            floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 60000
        )
        ",
    )
    .bind(principal)
    .bind(Uuid::new_v4())
    .bind(vec![1_u8; 17])
    .bind(vec![2_u8; 12])
    .bind(vec![3_u8; 32])
    .execute(pool)
    .await?;
    Ok(())
}

fn github_memberships(include_team: bool) -> GithubMembershipSnapshot {
    let organization_id = GithubOrganizationId::new(100).expect("organization ID");
    let organization_login =
        GithubOrganizationLogin::new("automata-ci").expect("organization login");
    let teams = include_team.then(|| {
        GithubTeam::new(
            GithubTeamId::new(200).expect("team ID"),
            organization_id,
            organization_login.clone(),
            GithubTeamSlug::new("maintainers").expect("team slug"),
        )
    });
    GithubMembershipSnapshot::new(
        [GithubOrganizationMembership::new(
            organization_id,
            organization_login,
            GithubOrganizationMembershipRole::Member,
        )],
        teams,
    )
    .expect("GitHub memberships")
}

fn github_snapshot_request(
    id: Uuid,
    memberships: GithubMembershipSnapshot,
    observed_at: u64,
    valid_until: u64,
) -> PersistGithubMembershipSnapshot {
    PersistGithubMembershipSnapshot::new(
        TenantId::new("tenant-a").expect("tenant"),
        PrincipalId::new(PRINCIPAL_ID).expect("principal"),
        ProviderSubject::new("42").expect("provider subject"),
        TokenVersion::new(7).expect("token version"),
        GithubMembershipObservation::new(
            GithubMembershipSnapshotId::from_uuid(id).expect("snapshot ID"),
            memberships,
            UnixTimestamp::from_seconds(observed_at),
            UnixTimestamp::from_seconds(valid_until),
        )
        .expect("observation"),
    )
    .expect("snapshot request")
}

#[allow(clippy::too_many_arguments)]
async fn insert_github_mapping(
    pool: &PgPool,
    tenant_id: &str,
    organization_id: i64,
    team_id: Option<i64>,
    role_id: Uuid,
    scope_kind: &str,
    repository_id: Option<Uuid>,
    runner_group_id: Option<Uuid>,
    status: &str,
) -> TestResult<Uuid> {
    let id = Uuid::new_v4();
    let team_slug = team_id.map(|_| "maintainers");
    let disabled_at_ms = (status == "disabled").then_some(100_000_i64);
    sqlx::query(
        r"
        INSERT INTO github_role_mappings (
            tenant_id,id,provider_id,organization_id,organization_login,
            team_id,team_slug,role_id,scope_kind,repository_id,runner_group_id,
            status,created_at_ms,updated_at_ms,disabled_at_ms
        ) VALUES ($1,$2,'github',$3,'display-name-only',$4,$5,$6,$7,$8,$9,
                  $10,100000,100000,$11)
        ",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(organization_id)
    .bind(team_id)
    .bind(team_slug)
    .bind(role_id)
    .bind(scope_kind)
    .bind(repository_id)
    .bind(runner_group_id)
    .bind(status)
    .bind(disabled_at_ms)
    .execute(pool)
    .await?;
    Ok(id)
}

async fn insert_role(pool: &PgPool, name: &str) -> TestResult<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id,id,name,display_name,created_at_ms,updated_at_ms
        ) VALUES ('tenant-a',$1,$2,$2,100000,100000)
        ",
    )
    .bind(id)
    .bind(name)
    .execute(pool)
    .await?;
    Ok(id)
}

async fn bind_role(
    pool: &PgPool,
    principal: Uuid,
    role: Uuid,
    scope: &str,
    repository: Option<Uuid>,
    runner_group: Option<Uuid>,
    valid_until_ms: Option<i64>,
) -> TestResult<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id,id,principal_id,role_id,scope_kind,repository_id,
            runner_group_id,created_at_ms,valid_until_ms
        ) VALUES ('tenant-a',$1,$2,$3,$4,$5,$6,100000,$7)
        ",
    )
    .bind(id)
    .bind(principal)
    .bind(role)
    .bind(scope)
    .bind(repository)
    .bind(runner_group)
    .bind(valid_until_ms.map(rebased_milliseconds))
    .execute(pool)
    .await?;
    Ok(id)
}

async fn current_revision(pool: &PgPool, principal: Uuid) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id='tenant-a' AND principal_id=$1",
    )
    .bind(principal)
    .fetch_one(pool)
    .await?)
}

struct SessionSeed {
    id: Uuid,
    digest_byte: u8,
    authorization_revision: i64,
    issued_at_ms: i64,
    idle_expires_at_ms: i64,
    expires_at_ms: i64,
}

async fn seed_session(pool: &PgPool, principal: Uuid, seed: SessionSeed) -> TestResult {
    seed_session_for_provider(pool, principal, "github", "42", seed).await
}

async fn seed_session_for_provider(
    pool: &PgPool,
    principal: Uuid,
    provider_id: &str,
    provider_subject: &str,
    seed: SessionSeed,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id,tenant_id,principal_id,provider_id,provider_subject,
            session_kind,audience,token_hash,token_hash_key_id,
            authorization_revision,issued_at_ms,last_seen_at_ms,
            idle_expires_at_ms,expires_at_ms
        ) VALUES ($1,'tenant-a',$2,$3,$4,'browser','automata.web',
                  $5,'session-hmac-v1',$6,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                      + ($7 - $10),
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                      + ($7 - $10),
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                      + ($8 - $10),
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                      + ($9 - $10))
        ",
    )
    .bind(seed.id)
    .bind(principal)
    .bind(provider_id)
    .bind(provider_subject)
    .bind(vec![seed.digest_byte; 32])
    .bind(seed.authorization_revision)
    .bind(seed.issued_at_ms)
    .bind(seed.idle_expires_at_ms)
    .bind(seed.expires_at_ms)
    .bind(TEST_REFERENCE_MILLISECONDS)
    .execute(pool)
    .await?;
    Ok(())
}

async fn wait_for_resolver_race_gate(pool: &PgPool) -> TestResult<bool> {
    for _ in 0..200 {
        let waiting = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM pg_stat_activity
                WHERE datname = current_database()
                  AND wait_event_type = 'Lock'
                  AND wait_event = 'advisory'
            )
            ",
        )
        .fetch_one(pool)
        .await?;
        if waiting {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(false)
}

async fn wait_for_resolver_session_lock(pool: &PgPool) -> TestResult<bool> {
    for _ in 0..200 {
        let waiting = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM pg_stat_activity
                WHERE datname = current_database()
                  AND pid <> pg_backend_pid()
                  AND cardinality(pg_blocking_pids(pid)) > 0
            )
            ",
        )
        .fetch_one(pool)
        .await?;
        if waiting {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(false)
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn request_auth_resolves_current_exact_scopes_and_revision_changes() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        let repository_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repositories (
                id,tenant_id,scm_provider,provider_repository_id,owner,name,
                created_at_ms,updated_at_ms
            ) VALUES ($1,'tenant-a','github','100','automata-ci','automata',100000,100000)
            ",
        )
        .bind(repository_id)
        .execute(pool)
        .await?;
        let runner_group_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO runner_groups (
                id,tenant_id,name,normalized_name,created_at_ms,updated_at_ms
            ) VALUES ($1,'tenant-a','Trusted','trusted',100000,100000)
            ",
        )
        .bind(runner_group_id)
        .execute(pool)
        .await?;

        let tenant_role = insert_role(pool, "viewer").await?;
        let repository_role = insert_role(pool, "repository-reader").await?;
        let runner_role = insert_role(pool, "runner-operator").await?;
        let expired_role = insert_role(pool, "expired-reader").await?;
        let administrator_role = insert_role(pool, "administrator").await?;
        bind_role(pool, principal, tenant_role, "tenant", None, None, None).await?;
        let repository_binding = bind_role(
            pool,
            principal,
            repository_role,
            "repository",
            Some(repository_id),
            None,
            None,
        )
        .await?;
        bind_role(
            pool,
            principal,
            runner_role,
            "runner_group",
            None,
            Some(runner_group_id),
            None,
        )
        .await?;
        bind_role(
            pool,
            principal,
            expired_role,
            "tenant",
            None,
            None,
            Some(150_000),
        )
        .await?;
        bind_role(
            pool,
            principal,
            administrator_role,
            "tenant",
            None,
            None,
            None,
        )
        .await?;
        let revision = current_revision(pool, principal).await?;
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: Uuid::parse_str(SESSION_ID)?,
                digest_byte: 7,
                authorization_revision: revision,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 300_000,
                expires_at_ms: 400_000,
            },
        )
        .await?;
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());

        let ResolveAuthenticatedRequestOutcome::Authenticated(snapshot) = resolver
            .resolve(&request(7, SessionKind::Browser, 150))
            .await?
        else {
            panic!("session should authenticate")
        };
        assert_eq!(snapshot.viewer().display_name(), "Durable Viewer");
        assert_eq!(snapshot.human().login(), "octocat");
        let grants = snapshot
            .authorization()
            .role_grants()
            .expect("authenticated grants");
        let by_role: BTreeMap<_, _> = grants
            .iter()
            .map(|grant| (grant.role().as_str(), grant.scope()))
            .collect();
        assert_eq!(by_role.len(), 4);
        assert!(matches!(
            by_role.get("viewer"),
            Some(AuthorizationScope::Tenant { .. })
        ));
        assert_eq!(
            by_role
                .get("repository-reader")
                .and_then(|scope| scope.repository_resource())
                .map(|resource| resource.repository_id().as_uuid()),
            Some(repository_id)
        );
        assert_eq!(
            by_role
                .get("runner-operator")
                .and_then(|scope| scope.runner_group_resource())
                .map(|resource| resource.runner_group_id().as_uuid()),
            Some(runner_group_id)
        );
        assert!(!by_role.contains_key("expired-reader"));

        let delete = AuthorizationRequest::new(
            AuthorizationScope::tenant(snapshot.session().identity().tenant_id().clone()),
            Permission::new("tenant:delete").expect("permission"),
        );
        assert!(!CompositeAuthorizationPolicy::default().allows(snapshot.authorization(), &delete));
        assert!(matches!(
            resolver.resolve(&request(7, SessionKind::Cli, 150)).await?,
            ResolveAuthenticatedRequestOutcome::WrongKindOrAudience
        ));

        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id,role_id,permission_name,granted_at_ms
            ) VALUES ('tenant-a',$1,'runs:read',160000)
            ",
        )
        .bind(tenant_role)
        .execute(pool)
        .await?;
        let permission_revision = current_revision(pool, principal).await?;
        assert_eq!(permission_revision, revision + 1);
        assert_eq!(
            resolver
                .resolve(&request(7, SessionKind::Browser, 160))
                .await?,
            ResolveAuthenticatedRequestOutcome::AuthorizationRevisionChanged {
                session_revision: u64::try_from(revision)?,
                current_revision: u64::try_from(permission_revision)?,
            }
        );
        sqlx::query("UPDATE human_sessions SET authorization_revision=$1 WHERE id=$2")
            .bind(permission_revision)
            .bind(Uuid::parse_str(SESSION_ID)?)
            .execute(pool)
            .await?;

        sqlx::query(
            r"
            UPDATE rbac_role_bindings
            SET status='revoked', revoked_at_ms=170000,
                revocation_reason='test revoke', revision=revision+1
            WHERE tenant_id='tenant-a' AND id=$1
            ",
        )
        .bind(repository_binding)
        .execute(pool)
        .await?;
        let revoke_revision = current_revision(pool, principal).await?;
        assert_eq!(revoke_revision, permission_revision + 1);
        assert!(matches!(
            resolver
                .resolve(&request(7, SessionKind::Browser, 170))
                .await?,
            ResolveAuthenticatedRequestOutcome::AuthorizationRevisionChanged { .. }
        ));
        sqlx::query("UPDATE human_sessions SET authorization_revision=$1 WHERE id=$2")
            .bind(revoke_revision)
            .bind(Uuid::parse_str(SESSION_ID)?)
            .execute(pool)
            .await?;
        let ResolveAuthenticatedRequestOutcome::Authenticated(snapshot) = resolver
            .resolve(&request(7, SessionKind::Browser, 170))
            .await?
        else {
            panic!("refreshed revision should authenticate")
        };
        assert!(
            !snapshot
                .authorization()
                .role_grants()
                .expect("grants")
                .iter()
                .any(|grant| grant.role().as_str() == "repository-reader")
        );

        let late_role = insert_role(pool, "late-reader").await?;
        bind_role(pool, principal, late_role, "tenant", None, None, None).await?;
        let grant_revision = current_revision(pool, principal).await?;
        assert_eq!(grant_revision, revoke_revision + 1);
        assert_eq!(
            resolver
                .resolve(&request(7, SessionKind::Browser, 180))
                .await?,
            ResolveAuthenticatedRequestOutcome::AuthorizationRevisionChanged {
                session_revision: u64::try_from(revoke_revision)?,
                current_revision: u64::try_from(grant_revision)?,
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn request_auth_distinguishes_status_and_lifetime_failures() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        let revision = current_revision(pool, principal).await?;
        let session_id = Uuid::parse_str(SESSION_ID)?;
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: session_id,
                digest_byte: 8,
                authorization_revision: revision,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 300_000,
                expires_at_ms: 400_000,
            },
        )
        .await?;
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: Uuid::new_v4(),
                digest_byte: 9,
                authorization_revision: revision,
                issued_at_ms: 200_000,
                idle_expires_at_ms: 300_000,
                expires_at_ms: 400_000,
            },
        )
        .await?;
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());

        assert!(matches!(
            resolver
                .resolve(&request(99, SessionKind::Browser, 150))
                .await?,
            ResolveAuthenticatedRequestOutcome::NotFound
        ));
        assert!(matches!(
            resolver
                .resolve(&request(9, SessionKind::Browser, 150))
                .await?,
            ResolveAuthenticatedRequestOutcome::NotYetValid
        ));

        sqlx::query(
            r"
            UPDATE human_principals
            SET status='disabled', disabled_at_ms=150000,
                disabled_reason='test', updated_at_ms=150000, revision=revision+1
            WHERE id=$1
            ",
        )
        .bind(principal)
        .execute(pool)
        .await?;
        assert!(matches!(
            resolver
                .resolve(&request(8, SessionKind::Browser, 150))
                .await?,
            ResolveAuthenticatedRequestOutcome::PrincipalDisabled
        ));
        sqlx::query(
            r"
            UPDATE human_principals
            SET status='active', disabled_at_ms=NULL, disabled_reason=NULL,
                updated_at_ms=160000, revision=revision+1
            WHERE id=$1
            ",
        )
        .bind(principal)
        .execute(pool)
        .await?;

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended', suspended_at_ms=160000,
                suspended_reason='test', updated_at_ms=160000, revision=revision+1
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(principal)
        .execute(pool)
        .await?;
        assert!(matches!(
            resolver
                .resolve(&request(8, SessionKind::Browser, 160))
                .await?,
            ResolveAuthenticatedRequestOutcome::MembershipSuspended
        ));
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='active', suspended_at_ms=NULL, suspended_reason=NULL,
                updated_at_ms=170000, revision=revision+1
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(principal)
        .execute(pool)
        .await?;
        let revision = current_revision(pool, principal).await?;
        sqlx::query("UPDATE human_sessions SET authorization_revision=$1 WHERE id=$2")
            .bind(revision)
            .bind(session_id)
            .execute(pool)
            .await?;

        sqlx::query(
            r"
            UPDATE human_sessions
            SET revoked_at_ms=(
                    floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 30000
                ),
                revocation_reason='test'
            WHERE id=$1
            ",
        )
        .bind(session_id)
        .execute(pool)
        .await?;
        assert!(matches!(
            resolver
                .resolve(&request(8, SessionKind::Browser, 180))
                .await?,
            ResolveAuthenticatedRequestOutcome::Revoked
        ));
        sqlx::query(
            r"
            UPDATE human_sessions
            SET revoked_at_ms=NULL, revocation_reason=NULL,
                idle_expires_at_ms=(
                    floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
                )
            WHERE id=$1
            ",
        )
        .bind(session_id)
        .execute(pool)
        .await?;
        assert!(matches!(
            resolver
                .resolve(&request(8, SessionKind::Browser, 190))
                .await?,
            ResolveAuthenticatedRequestOutcome::Expired
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn request_auth_role_mutation_cannot_create_a_mixed_snapshot() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        let role = insert_role(pool, "race-reader").await?;
        let binding = bind_role(pool, principal, role, "tenant", None, None, None).await?;
        let revision = current_revision(pool, principal).await?;
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: Uuid::parse_str(SESSION_ID)?,
                digest_byte: 10,
                authorization_revision: revision,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 300_000,
                expires_at_ms: 400_000,
            },
        )
        .await?;

        // Hold the same tenant mutex used by management mutation. The resolver
        // must wait for the mutation, then lock and classify the post-mutation
        // session/revision graph as one coherent authorization snapshot.
        let mut gate = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('tenant-a', 731662009))")
            .execute(&mut *gate)
            .await?;
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        let resolution = tokio::spawn(async move {
            resolver
                .resolve(&request(10, SessionKind::Browser, 150))
                .await
        });

        if !wait_for_resolver_race_gate(pool).await? {
            return Err("request-auth resolver did not reach the deterministic race gate".into());
        }

        sqlx::query(
            r"
            UPDATE rbac_role_bindings
            SET status='revoked', revoked_at_ms=150000,
                revocation_reason='interleaved revoke', revision=revision+1
            WHERE tenant_id='tenant-a' AND id=$1
            ",
        )
        .bind(binding)
        .execute(&mut *gate)
        .await?;
        gate.commit().await?;

        let outcome = resolution.await??;
        assert_eq!(
            outcome,
            ResolveAuthenticatedRequestOutcome::AuthorizationRevisionChanged {
                session_revision: u64::try_from(revision)?,
                current_revision: u64::try_from(revision + 1)?,
            }
        );
        assert_eq!(current_revision(pool, principal).await?, revision + 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn request_auth_revalidates_discovered_tenant_after_the_authority_lock() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        sqlx::query(
            "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ('tenant-b','Tenant B',100000,100000)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO tenant_human_memberships (
                tenant_id,principal_id,status,authorization_revision,
                created_at_ms,updated_at_ms
            ) VALUES ('tenant-b',$1,'active',1,100000,100000)
            ",
        )
        .bind(principal)
        .execute(pool)
        .await?;
        let revision = current_revision(pool, principal).await?;
        let session_id = Uuid::parse_str(SESSION_ID)?;
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: session_id,
                digest_byte: 0x6a,
                authorization_revision: revision,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 300_000,
                expires_at_ms: 400_000,
            },
        )
        .await?;
        sqlx::query("ALTER TABLE human_sessions DISABLE TRIGGER USER")
            .execute(pool)
            .await?;

        let mut gate = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('tenant-a', 731662009))")
            .execute(&mut *gate)
            .await?;
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        let resolution = tokio::spawn(async move {
            resolver
                .resolve(&request(0x6a, SessionKind::Browser, 150))
                .await
        });
        if !wait_for_resolver_race_gate(pool).await? {
            gate.rollback().await?;
            return Err("request auth did not wait after tenant discovery".into());
        }
        sqlx::query("UPDATE human_sessions SET tenant_id='tenant-b' WHERE id=$1")
            .bind(session_id)
            .execute(pool)
            .await?;
        gate.commit().await?;
        assert_eq!(
            resolution
                .await?
                .expect_err("locked tenant drift must fail closed"),
            RequestAuthenticationResolverError::CorruptData
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn request_auth_rejects_clock_skew_and_resamples_after_session_lock_wait() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        let database_now_ms = clock.now().await?;
        clock.set(database_now_ms.div_euclid(1_000) * 1_000).await?;
        let principal = seed_identity(pool).await?;
        let revision = current_revision(pool, principal).await?;
        let session_id = Uuid::parse_str(SESSION_ID)?;
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: session_id,
                digest_byte: 11,
                authorization_revision: revision,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 300_000,
                expires_at_ms: 400_000,
            },
        )
        .await?;
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());

        let database_now = database_now_seconds(pool).await?;
        assert_eq!(
            resolver
                .resolve(&request_at(11, SessionKind::Browser, database_now + 61,))
                .await,
            Err(RequestAuthenticationResolverError::InvalidRequest)
        );
        let database_now = database_now_seconds(pool).await?;
        assert_eq!(
            resolver
                .resolve(&request_at(11, SessionKind::Browser, database_now - 61,))
                .await,
            Err(RequestAuthenticationResolverError::InvalidRequest)
        );

        let mut gate = pool.begin().await?;
        sqlx::query("SELECT id FROM human_sessions WHERE id=$1 FOR UPDATE")
            .bind(session_id)
            .execute(&mut *gate)
            .await?;
        sqlx::query(
            r"
            UPDATE human_sessions
            SET idle_expires_at_ms =
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 1000
            WHERE id = $1
            ",
        )
        .bind(session_id)
        .execute(&mut *gate)
        .await?;

        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        let request = request(11, SessionKind::Browser, 150);
        let resolution = tokio::spawn(async move { resolver.resolve(&request).await });
        if !wait_for_resolver_session_lock(pool).await? {
            gate.rollback().await?;
            return Err(format!(
                "request-auth resolver did not wait on the exact session lock: {:?}",
                resolution.await?
            )
            .into());
        }
        clock.advance(1_100).await?;
        gate.commit().await?;

        assert_eq!(
            resolution.await??,
            ResolveAuthenticatedRequestOutcome::Expired
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn request_auth_resolves_only_exact_current_github_numeric_mappings() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        seed_provider_token(pool, principal).await?;
        let repository_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repositories (
                id,tenant_id,scm_provider,provider_repository_id,owner,name,
                created_at_ms,updated_at_ms
            ) VALUES ($1,'tenant-a','github','100','automata-ci','automata',100000,100000)
            ",
        )
        .bind(repository_id)
        .execute(pool)
        .await?;
        let runner_group_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO runner_groups (
                id,tenant_id,name,normalized_name,created_at_ms,updated_at_ms
            ) VALUES ($1,'tenant-a','Trusted','trusted',100000,100000)
            ",
        )
        .bind(runner_group_id)
        .execute(pool)
        .await?;

        let organization_role = insert_role(pool, "github-org-reader").await?;
        let team_repository_role = insert_role(pool, "github-team-repository").await?;
        let team_runner_role = insert_role(pool, "github-team-runner").await?;
        let wrong_organization_role = insert_role(pool, "wrong-organization").await?;
        let wrong_team_role = insert_role(pool, "wrong-team").await?;
        let disabled_role = insert_role(pool, "disabled-mapping").await?;
        let administrator_role = insert_role(pool, "administrator").await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            None,
            organization_role,
            "tenant",
            None,
            None,
            "active",
        )
        .await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            Some(200),
            team_repository_role,
            "repository",
            Some(repository_id),
            None,
            "active",
        )
        .await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            Some(200),
            team_runner_role,
            "runner_group",
            None,
            Some(runner_group_id),
            "active",
        )
        .await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            101,
            None,
            wrong_organization_role,
            "tenant",
            None,
            None,
            "active",
        )
        .await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            Some(201),
            wrong_team_role,
            "tenant",
            None,
            None,
            "active",
        )
        .await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            None,
            disabled_role,
            "tenant",
            None,
            None,
            "disabled",
        )
        .await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            None,
            administrator_role,
            "tenant",
            None,
            None,
            "active",
        )
        .await?;

        sqlx::query(
            "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ('tenant-b','Tenant B',100000,100000)",
        )
        .execute(pool)
        .await?;
        let cross_tenant_role = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO rbac_roles (
                tenant_id,id,name,display_name,created_at_ms,updated_at_ms
            ) VALUES ('tenant-b',$1,'cross-tenant','cross-tenant',100000,100000)
            ",
        )
        .bind(cross_tenant_role)
        .execute(pool)
        .await?;
        insert_github_mapping(
            pool,
            "tenant-b",
            100,
            None,
            cross_tenant_role,
            "tenant",
            None,
            None,
            "active",
        )
        .await?;

        let membership_repository = PostgresGithubMembershipRepository::new(pool.clone());
        let database_now = database_now_seconds(pool).await?;
        assert!(matches!(
            membership_repository
                .persist(&github_snapshot_request(
                    Uuid::new_v4(),
                    github_memberships(true),
                    database_now - 50,
                    database_now + 250,
                ))
                .await?,
            PersistGithubMembershipSnapshotOutcome::Stored {
                authorization_changed: true,
                ..
            }
        ));
        let first_revision = current_revision(pool, principal).await?;
        let session_id = Uuid::new_v4();
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: session_id,
                digest_byte: 40,
                authorization_revision: first_revision,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 400_000,
                expires_at_ms: 500_000,
            },
        )
        .await?;
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());

        let ResolveAuthenticatedRequestOutcome::Authenticated(snapshot) = resolver
            .resolve(&request(40, SessionKind::Browser, 150))
            .await?
        else {
            panic!("current GitHub snapshot should authenticate")
        };
        let grants = snapshot
            .authorization()
            .role_grants()
            .expect("authenticated grants");
        let by_role: BTreeMap<_, _> = grants
            .iter()
            .map(|grant| (grant.role().as_str(), grant.scope()))
            .collect();
        assert_eq!(by_role.len(), 4);
        assert!(matches!(
            by_role.get("github-org-reader"),
            Some(AuthorizationScope::Tenant { .. })
        ));
        assert_eq!(
            by_role
                .get("github-team-repository")
                .and_then(|scope| scope.repository_resource())
                .map(|resource| resource.repository_id().as_uuid()),
            Some(repository_id)
        );
        assert_eq!(
            by_role
                .get("github-team-runner")
                .and_then(|scope| scope.runner_group_resource())
                .map(|resource| resource.runner_group_id().as_uuid()),
            Some(runner_group_id)
        );
        for absent in [
            "wrong-organization",
            "wrong-team",
            "disabled-mapping",
            "cross-tenant",
        ] {
            assert!(!by_role.contains_key(absent));
        }
        let delete = AuthorizationRequest::new(
            AuthorizationScope::tenant(snapshot.session().identity().tenant_id().clone()),
            Permission::new("tenant:delete").expect("permission"),
        );
        assert!(!CompositeAuthorizationPolicy::default().allows(snapshot.authorization(), &delete));

        assert!(matches!(
            membership_repository
                .persist(&github_snapshot_request(
                    Uuid::new_v4(),
                    GithubMembershipSnapshot::default(),
                    database_now - 10,
                    database_now,
                ))
                .await?,
            PersistGithubMembershipSnapshotOutcome::Stored {
                authorization_changed: true,
                ..
            }
        ));
        let expiry_revision = current_revision(pool, principal).await?;
        sqlx::query("UPDATE human_sessions SET authorization_revision=$1 WHERE id=$2")
            .bind(expiry_revision)
            .bind(session_id)
            .execute(pool)
            .await?;
        let ResolveAuthenticatedRequestOutcome::Authenticated(stale) = resolver
            .resolve(&request(40, SessionKind::Browser, 200))
            .await?
        else {
            panic!("snapshot expiry only removes grants")
        };
        assert!(
            stale
                .authorization()
                .role_grants()
                .expect("grants")
                .is_empty()
        );

        assert!(matches!(
            membership_repository
                .persist(&github_snapshot_request(
                    Uuid::new_v4(),
                    github_memberships(false),
                    database_now - 5,
                    database_now + 90,
                ))
                .await?,
            PersistGithubMembershipSnapshotOutcome::Stored {
                authorization_changed: true,
                ..
            }
        ));
        let snapshot_revision = current_revision(pool, principal).await?;
        assert_eq!(snapshot_revision, expiry_revision + 1);
        assert!(matches!(
            resolver
                .resolve(&request(40, SessionKind::Browser, 220))
                .await?,
            ResolveAuthenticatedRequestOutcome::AuthorizationRevisionChanged { .. }
        ));
        sqlx::query("UPDATE human_sessions SET authorization_revision=$1 WHERE id=$2")
            .bind(snapshot_revision)
            .bind(session_id)
            .execute(pool)
            .await?;
        let ResolveAuthenticatedRequestOutcome::Authenticated(snapshot) = resolver
            .resolve(&request(40, SessionKind::Browser, 220))
            .await?
        else {
            panic!("refreshed session revision should authenticate")
        };
        assert!(
            snapshot
                .authorization()
                .role_grants()
                .expect("grants")
                .iter()
                .all(|grant| !grant.role().as_str().starts_with("github-team-"))
        );

        let late_role = insert_role(pool, "late-github-role").await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            None,
            late_role,
            "tenant",
            None,
            None,
            "active",
        )
        .await?;
        assert!(matches!(
            resolver
                .resolve(&request(40, SessionKind::Browser, 230))
                .await?,
            ResolveAuthenticatedRequestOutcome::AuthorizationRevisionChanged { .. }
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn github_mappings_require_the_exact_github_session_identity() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        seed_provider_token(pool, principal).await?;

        let direct_role = insert_role(pool, "direct-reader").await?;
        bind_role(pool, principal, direct_role, "tenant", None, None, None).await?;
        let mapped_role = insert_role(pool, "github-org-reader").await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            None,
            mapped_role,
            "tenant",
            None,
            None,
            "active",
        )
        .await?;
        let membership_repository = PostgresGithubMembershipRepository::new(pool.clone());
        let database_now = database_now_seconds(pool).await?;
        assert!(matches!(
            membership_repository
                .persist(&github_snapshot_request(
                    Uuid::new_v4(),
                    github_memberships(false),
                    database_now - 50,
                    database_now + 250,
                ))
                .await?,
            PersistGithubMembershipSnapshotOutcome::Stored { .. }
        ));

        sqlx::query(
            r"
            INSERT INTO human_provider_identities (
                principal_id,provider_id,provider_subject,provider_login,
                normalized_login,display_name,first_authenticated_at_ms,
                last_authenticated_at_ms,last_observed_at_ms,created_at_ms,updated_at_ms
            ) VALUES ($1,'gitlab','9001','gitlab-user','gitlab-user','GitLab Viewer',
                      100000,120000,120000,100000,120000)
            ",
        )
        .bind(principal)
        .execute(pool)
        .await?;
        let revision = current_revision(pool, principal).await?;
        seed_session_for_provider(
            pool,
            principal,
            "gitlab",
            "9001",
            SessionSeed {
                id: Uuid::new_v4(),
                digest_byte: 41,
                authorization_revision: revision,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 400_000,
                expires_at_ms: 500_000,
            },
        )
        .await?;

        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        let ResolveAuthenticatedRequestOutcome::Authenticated(snapshot) = resolver
            .resolve(&request(41, SessionKind::Browser, 150))
            .await?
        else {
            panic!("non-GitHub session should authenticate")
        };
        assert_eq!(snapshot.human().provider_id().as_str(), "gitlab");
        assert_eq!(snapshot.human().provider_subject().as_str(), "9001");
        let roles: BTreeSet<_> = snapshot
            .authorization()
            .role_grants()
            .expect("authenticated grants")
            .iter()
            .map(|grant| grant.role().as_str())
            .collect();
        assert_eq!(roles, BTreeSet::from(["direct-reader"]));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn github_snapshot_normalized_display_identity_conflicts_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        let snapshot_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','42',7,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 50000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 150000
            )
            ",
        )
        .bind(snapshot_id)
        .bind(principal)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id,snapshot_id,organization_id,organization_login,membership_role
            ) VALUES
                ('tenant-a',$1,100,'AUTOMATA-CI','member'),
                ('tenant-a',$1,101,'automata-ci','member')
            ",
        )
        .bind(snapshot_id)
        .execute(pool)
        .await?;
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: Uuid::new_v4(),
                digest_byte: 42,
                authorization_revision: current_revision(pool, principal).await?,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 400_000,
                expires_at_ms: 500_000,
            },
        )
        .await?;
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        assert_eq!(
            resolver
                .resolve(&request(42, SessionKind::Browser, 150))
                .await,
            Err(RequestAuthenticationResolverError::CorruptData)
        );

        sqlx::query(
            "DELETE FROM github_organization_membership_observations WHERE tenant_id='tenant-a' AND snapshot_id=$1 AND organization_id=101",
        )
        .bind(snapshot_id)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_team_membership_observations (
                tenant_id,snapshot_id,organization_id,team_id,team_slug
            ) VALUES
                ('tenant-a',$1,100,200,'Maintainers'),
                ('tenant-a',$1,100,201,'maintainers')
            ",
        )
        .bind(snapshot_id)
        .execute(pool)
        .await?;
        assert_eq!(
            resolver
                .resolve(&request(42, SessionKind::Browser, 160))
                .await,
            Err(RequestAuthenticationResolverError::CorruptData)
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn nullable_github_observation_predicates_fail_closed_before_mapping_grants() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        let mapped_role = insert_role(pool, "nullable-observation-mapping").await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            None,
            mapped_role,
            "tenant",
            None,
            None,
            "active",
        )
        .await?;

        let snapshot_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','42',7,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 50000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 150000
            )
            ",
        )
        .bind(snapshot_id)
        .bind(principal)
        .execute(pool)
        .await?;
        sqlx::query(
            "ALTER TABLE github_organization_membership_observations ALTER COLUMN membership_role DROP NOT NULL",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id,snapshot_id,organization_id,organization_login,membership_role
            ) VALUES ('tenant-a',$1,100,'automata-ci',NULL)
            ",
        )
        .bind(snapshot_id)
        .execute(pool)
        .await?;
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: Uuid::new_v4(),
                digest_byte: 43,
                authorization_revision: current_revision(pool, principal).await?,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 400_000,
                expires_at_ms: 500_000,
            },
        )
        .await?;

        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        assert_eq!(
            resolver
                .resolve(&request(43, SessionKind::Browser, 150))
                .await,
            Err(RequestAuthenticationResolverError::CorruptData),
            "a NULL integrity predicate must invalidate the snapshot before its numeric mapping can grant authority"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn corrupt_github_snapshot_role_and_resource_parents_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        let session_id = Uuid::new_v4();
        seed_session(
            pool,
            principal,
            SessionSeed {
                id: session_id,
                digest_byte: 41,
                authorization_revision: current_revision(pool, principal).await?,
                issued_at_ms: 100_000,
                idle_expires_at_ms: 400_000,
                expires_at_ms: 500_000,
            },
        )
        .await?;
        let snapshot_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO github_membership_snapshots (
                tenant_id,id,principal_id,provider_id,provider_subject,
                provider_token_version,observed_at_ms,valid_until_ms
            ) VALUES (
                'tenant-a',$1,$2,'github','42',7,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 50000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 150000
            )
            ",
        )
        .bind(snapshot_id)
        .bind(principal)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id,snapshot_id,organization_id,organization_login,membership_role
            ) VALUES ('tenant-a',$1,100,'automata-ci','member')
            ",
        )
        .bind(snapshot_id)
        .execute(pool)
        .await?;
        sqlx::query(
            "ALTER TABLE github_team_membership_observations DROP CONSTRAINT github_team_membership_observations_organization",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_team_membership_observations (
                tenant_id,snapshot_id,organization_id,team_id,team_slug
            ) VALUES ('tenant-a',$1,101,200,'orphan')
            ",
        )
        .bind(snapshot_id)
        .execute(pool)
        .await?;
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        assert_eq!(
            resolver
                .resolve(&request(41, SessionKind::Browser, 150))
                .await,
            Err(RequestAuthenticationResolverError::CorruptData)
        );

        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id,snapshot_id,organization_id,organization_login,membership_role
            ) VALUES ('tenant-a',$1,101,'other-org','member')
            ",
        )
        .bind(snapshot_id)
        .execute(pool)
        .await?;
        sqlx::query(
            "ALTER TABLE github_role_mappings DROP CONSTRAINT github_role_mappings_role",
        )
        .execute(pool)
        .await?;
        let missing_role_mapping = insert_github_mapping(
            pool,
            "tenant-a",
            100,
            None,
            Uuid::new_v4(),
            "tenant",
            None,
            None,
            "active",
        )
        .await?;
        sqlx::query("UPDATE human_sessions SET authorization_revision=$1 WHERE id=$2")
            .bind(current_revision(pool, principal).await?)
            .bind(session_id)
            .execute(pool)
            .await?;
        assert_eq!(
            resolver
                .resolve(&request(41, SessionKind::Browser, 160))
                .await,
            Err(RequestAuthenticationResolverError::CorruptData)
        );

        sqlx::query("DELETE FROM github_role_mappings WHERE tenant_id='tenant-a' AND id=$1")
            .bind(missing_role_mapping)
            .execute(pool)
            .await?;
        let role = insert_role(pool, "resource-parent-test").await?;
        sqlx::query(
            "ALTER TABLE github_role_mappings DROP CONSTRAINT github_role_mappings_repository",
        )
        .execute(pool)
        .await?;
        insert_github_mapping(
            pool,
            "tenant-a",
            100,
            None,
            role,
            "repository",
            Some(Uuid::new_v4()),
            None,
            "active",
        )
        .await?;
        sqlx::query("UPDATE human_sessions SET authorization_revision=$1 WHERE id=$2")
            .bind(current_revision(pool, principal).await?)
            .bind(session_id)
            .execute(pool)
            .await?;
        assert_eq!(
            resolver
                .resolve(&request(41, SessionKind::Browser, 170))
                .await,
            Err(RequestAuthenticationResolverError::CorruptData)
        );
        Ok(())
    })
    .await
}
