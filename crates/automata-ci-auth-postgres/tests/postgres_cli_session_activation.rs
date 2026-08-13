use std::time::{SystemTime, UNIX_EPOCH};

use automata_ci_auth::{
    human::{PrincipalId, ProviderId, ProviderSubject, TenantId},
    request_auth::{
        RequestAuthenticationResolver, ResolveAuthenticatedRequest,
        ResolveAuthenticatedRequestOutcome,
    },
    session::{
        ActivateCliSession, ActivateCliSessionOutcome, CreateSession, CreateSessionOutcome,
        DurableSession, DurableSessionIdentity, HumanSessionRepository, ResolveSession,
        ResolveSessionOutcome, RevokeOwnSession, SessionId, SessionKind, SessionTokenDigest,
        SessionTokenDigestKeyId, SessionTokenLookup, TouchSession, TouchSessionOutcome,
    },
    time::UnixTimestamp,
};
use automata_ci_auth_postgres::{
    PostgresHumanSessionRepository, PostgresRequestAuthenticationResolver,
};
use automata_ci_postgres_test_support::TestClock;
use sqlx::PgPool;
use uuid::Uuid;

use super::support::{TestResult, run_with_database};

const TENANT: &str = "activation-tenant";
const SUBJECT: &str = "424242";

fn now() -> UnixTimestamp {
    UnixTimestamp::from_seconds(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_secs(),
    )
}

fn lookup(byte: u8) -> SessionTokenLookup {
    SessionTokenLookup::new(
        SessionTokenDigestKeyId::new("cli-activation-hmac-v1").expect("lookup key"),
        SessionTokenDigest::new([byte; 32]),
    )
}

fn session(
    id: Uuid,
    principal: Uuid,
    kind: SessionKind,
    authorization_revision: u64,
) -> DurableSession {
    let issued_at = now();
    DurableSession::new(
        DurableSessionIdentity::new(
            SessionId::new(id.hyphenated().to_string()).expect("session ID"),
            TenantId::new(TENANT).expect("tenant"),
            PrincipalId::new(principal.hyphenated().to_string()).expect("principal"),
            ProviderId::new("github").expect("provider"),
            ProviderSubject::new(SUBJECT).expect("subject"),
            kind,
        )
        .expect("durable identity"),
        authorization_revision,
        issued_at,
        issued_at,
        issued_at.checked_add(800).expect("idle expiry"),
        issued_at.checked_add(900).expect("absolute expiry"),
        None,
    )
    .expect("durable session")
}

async fn seed_actor(pool: &PgPool) -> TestResult<Uuid> {
    sqlx::query(
        "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,'Activation tenant',100000,100000)",
    )
    .bind(TENANT)
    .execute(pool)
    .await?;
    let principal = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO human_principals (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,'CLI user',100000,100000)",
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
        ) VALUES ($1,'github',$2,'octocat','octocat','Octocat',100000,100000,
                  100000,100000,100000)
        ",
    )
    .bind(principal)
    .bind(SUBJECT)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id,principal_id,status,authorization_revision,
            created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'active',1,100000,100000)
        ",
    )
    .bind(TENANT)
    .bind(principal)
    .execute(pool)
    .await?;
    Ok(principal)
}

async fn create(
    repository: &PostgresHumanSessionRepository,
    principal: Uuid,
    id: Uuid,
    kind: SessionKind,
    lookup: SessionTokenLookup,
    revision: u64,
) -> TestResult {
    assert_eq!(
        repository
            .create(CreateSession::new(
                lookup,
                session(id, principal, kind, revision),
            ))
            .await?,
        CreateSessionOutcome::Created
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn activation_final_write_resamples_after_a_statement_delay() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        let principal = seed_actor(pool).await?;
        let session_id = Uuid::new_v4();
        let cli_lookup = lookup(0x51);
        sqlx::query(
            r"
            INSERT INTO human_sessions (
                id,tenant_id,principal_id,provider_id,provider_subject,
                session_kind,audience,token_hash,token_hash_key_id,
                authorization_revision,issued_at_ms,last_seen_at_ms,
                idle_expires_at_ms,expires_at_ms,lifecycle_status,
                activation_deadline_ms
            ) VALUES (
                $1,$2,$3,'github',$4,'cli','automata.cli',$5,$6,1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 10000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 10000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 500000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 600000,
                'pending_activation',
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 2000
            )
            ",
        )
        .bind(session_id)
        .bind(TENANT)
        .bind(principal)
        .bind(SUBJECT)
        .bind(cli_lookup.digest().as_bytes().as_slice())
        .bind(cli_lookup.key_id().as_str())
        .execute(pool)
        .await?;
        let activation_deadline_ms: i64 =
            sqlx::query_scalar("SELECT activation_deadline_ms FROM human_sessions WHERE id=$1")
                .bind(session_id)
                .fetch_one(pool)
                .await?;
        clock
            .set(
                activation_deadline_ms
                    .checked_sub(1)
                    .expect("time immediately before activation expiry"),
            )
            .await?;
        sqlx::query(
            r"
            CREATE FUNCTION advance_cli_activation_test_clock() RETURNS trigger AS $$
            BEGIN
                UPDATE automata_test.__automata_test_clock
                SET now_ms = now_ms + 2100
                WHERE singleton;
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql
            ",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            CREATE TRIGGER advance_cli_activation_test_clock
            BEFORE UPDATE ON human_sessions
            FOR EACH STATEMENT EXECUTE FUNCTION advance_cli_activation_test_clock()
            ",
        )
        .execute(pool)
        .await?;

        let repository = PostgresHumanSessionRepository::new(pool.clone());
        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(cli_lookup, now()))
                .await?,
            ActivateCliSessionOutcome::ActivationExpired
        );
        let unchanged: (String, Option<i64>, i64, i64) = sqlx::query_as(
            "SELECT lifecycle_status,activated_at_ms,revision,(SELECT count(*) FROM security_audit_events WHERE action='auth.session.cli.activate') FROM human_sessions WHERE id=$1",
        )
        .bind(session_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(unchanged, ("pending_activation".to_owned(), None, 1, 0));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn active_cli_with_future_activation_fails_closed_at_post_lock_database_time() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_actor(pool).await?;
        let session_id = Uuid::new_v4();
        let cli_lookup = lookup(0x52);
        sqlx::query(
            r"
            INSERT INTO human_sessions (
                id,tenant_id,principal_id,provider_id,provider_subject,
                session_kind,audience,token_hash,token_hash_key_id,
                authorization_revision,issued_at_ms,last_seen_at_ms,
                idle_expires_at_ms,expires_at_ms,lifecycle_status,
                activation_deadline_ms,activated_at_ms
            ) VALUES (
                $1,$2,$3,'github',$4,'cli','automata.cli',$5,$6,1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 10000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 10000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 500000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 600000,
                'pending_activation',
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 290000,
                NULL
            )
            ",
        )
        .bind(session_id)
        .bind(TENANT)
        .bind(principal)
        .bind(SUBJECT)
        .bind(cli_lookup.digest().as_bytes().as_slice())
        .bind(cli_lookup.key_id().as_str())
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            UPDATE human_sessions
            SET lifecycle_status='active',
                activated_at_ms=
                    floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 30000,
                revision=revision+1
            WHERE id=$1
            ",
        )
        .bind(session_id)
        .execute(pool)
        .await?;

        let repository = PostgresHumanSessionRepository::new(pool.clone());
        assert_eq!(
            repository
                .resolve(&ResolveSession::new(
                    cli_lookup.clone(),
                    SessionKind::Cli,
                    now(),
                ))
                .await
                .expect_err("future activation must be corrupt"),
            automata_ci_auth::session::SessionRepositoryError::CorruptData
        );
        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(cli_lookup.clone(), now()))
                .await
                .expect_err("future activation must not replay as active"),
            automata_ci_auth::session::SessionRepositoryError::CorruptData
        );
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        assert_eq!(
            resolver
                .resolve(&ResolveAuthenticatedRequest::new(
                    cli_lookup,
                    SessionKind::Cli,
                    now(),
                ))
                .await
                .expect_err("request auth must reject future activation"),
            automata_ci_auth::request_auth::RequestAuthenticationResolverError::CorruptData
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn pending_cli_is_unusable_until_one_concurrent_activation_wins() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_actor(pool).await?;
        let repository = PostgresHumanSessionRepository::new(pool.clone());
        let resolver = PostgresRequestAuthenticationResolver::new(pool.clone());
        let session_id = Uuid::new_v4();
        let cli_lookup = lookup(1);
        create(
            &repository,
            principal,
            session_id,
            SessionKind::Cli,
            cli_lookup.clone(),
            1,
        )
        .await?;

        let lifecycle: (String, Option<i64>, Option<i64>, i64) = sqlx::query_as(
            "SELECT lifecycle_status,activation_deadline_ms,activated_at_ms,revision FROM human_sessions WHERE id=$1",
        )
        .bind(session_id)
        .fetch_one(pool)
        .await?;
        let issued_at_ms: i64 = sqlx::query_scalar(
            "SELECT issued_at_ms FROM human_sessions WHERE id=$1",
        )
        .bind(session_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(
            lifecycle,
            (
                "pending_activation".to_owned(),
                Some(issued_at_ms + 300_000),
                None,
                1
            )
        );
        assert!(matches!(
            repository
                .resolve(&ResolveSession::new(
                    cli_lookup.clone(),
                    SessionKind::Cli,
                    now(),
                ))
                .await?,
            ResolveSessionOutcome::NotYetValid
        ));
        assert!(matches!(
            repository
                .touch(&TouchSession::new(
                    cli_lookup.clone(),
                    SessionKind::Cli,
                    now(),
                    now().checked_add(350)?,
                )?)
                .await?,
            TouchSessionOutcome::NotYetValid
        ));
        assert_eq!(
            resolver
                .resolve(&ResolveAuthenticatedRequest::new(
                    cli_lookup.clone(),
                    SessionKind::Cli,
                    now(),
                ))
                .await?,
            ResolveAuthenticatedRequestOutcome::NotFound
        );

        let request = ActivateCliSession::new(cli_lookup.clone(), now());
        let first = repository.clone();
        let second = repository.clone();
        let (first, second) = tokio::join!(first.activate_cli(&request), second.activate_cli(&request));
        let outcomes = [first?, second?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ActivateCliSessionOutcome::Activated(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ActivateCliSessionOutcome::AlreadyActive(_)))
                .count(),
            1
        );
        let lifecycle: (String, Option<i64>, i64) = sqlx::query_as(
            "SELECT lifecycle_status,activated_at_ms,revision FROM human_sessions WHERE id=$1",
        )
        .bind(session_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(lifecycle.0, "active");
        assert!(lifecycle.1.is_some_and(|activated_at| {
            activated_at >= issued_at_ms && activated_at < issued_at_ms + 300_000
        }));
        assert_eq!(lifecycle.2, 2);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security_audit_events WHERE action='auth.session.cli.activate'",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(audit_count, 1);
        let audit: (Uuid, Uuid, i64, String) = sqlx::query_as(
            r"
            SELECT actor_principal_id,actor_session_id,
                   authorization_revision,resource_id
            FROM security_audit_events
            WHERE action='auth.session.cli.activate'
            ",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(
            audit,
            (
                principal,
                session_id,
                1,
                session_id.hyphenated().to_string(),
            )
        );
        assert!(matches!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    cli_lookup.clone(),
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::AlreadyActive(_)
        ));
        assert!(matches!(
            resolver
                .resolve(&ResolveAuthenticatedRequest::new(
                    cli_lookup,
                    SessionKind::Cli,
                    now(),
                ))
                .await?,
            ResolveAuthenticatedRequestOutcome::Authenticated(_)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn activation_closes_every_noncurrent_or_non_cli_state() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_actor(pool).await?;
        let repository = PostgresHumanSessionRepository::new(pool.clone());

        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    lookup(99),
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::NotFound
        );

        let browser_lookup = lookup(2);
        create(
            &repository,
            principal,
            Uuid::new_v4(),
            SessionKind::Browser,
            browser_lookup.clone(),
            1,
        )
        .await?;
        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    browser_lookup,
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::WrongKindOrAudience
        );

        let deadline_id = Uuid::new_v4();
        let deadline_lookup = lookup(3);
        sqlx::query(
            r"
            INSERT INTO human_sessions (
                id,tenant_id,principal_id,provider_id,provider_subject,
                session_kind,audience,token_hash,token_hash_key_id,
                authorization_revision,issued_at_ms,last_seen_at_ms,
                idle_expires_at_ms,expires_at_ms,lifecycle_status,
                activation_deadline_ms
            ) VALUES (
                $1,$2,$3,'github',$4,'cli','automata.cli',$5,$6,1,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 300000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 300000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 500000,
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 600000,
                'pending_activation',
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
            )
            ",
        )
        .bind(deadline_id)
        .bind(TENANT)
        .bind(principal)
        .bind(SUBJECT)
        .bind(deadline_lookup.digest().as_bytes().as_slice())
        .bind(deadline_lookup.key_id().as_str())
        .execute(pool)
        .await?;
        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    deadline_lookup,
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::ActivationExpired
        );

        let revoked_id = Uuid::new_v4();
        let revoked_lookup = lookup(4);
        create(
            &repository,
            principal,
            revoked_id,
            SessionKind::Cli,
            revoked_lookup.clone(),
            1,
        )
        .await?;
        repository
            .revoke_own(&RevokeOwnSession::new(
                TenantId::new(TENANT)?,
                PrincipalId::new(principal.hyphenated().to_string())?,
                SessionId::new(revoked_id.hyphenated().to_string())?,
                now(),
            ))
            .await?;
        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    revoked_lookup,
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::Revoked
        );

        let disabled_lookup = lookup(5);
        create(
            &repository,
            principal,
            Uuid::new_v4(),
            SessionKind::Cli,
            disabled_lookup.clone(),
            1,
        )
        .await?;
        sqlx::query(
            "UPDATE human_principals SET status='disabled',disabled_at_ms=150000,disabled_reason='test',updated_at_ms=150000,revision=revision+1 WHERE id=$1",
        )
        .bind(principal)
        .execute(pool)
        .await?;
        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    disabled_lookup,
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::PrincipalDisabled
        );
        sqlx::query(
            "UPDATE human_principals SET status='active',disabled_at_ms=NULL,disabled_reason=NULL,updated_at_ms=170000,revision=revision+1 WHERE id=$1",
        )
        .bind(principal)
        .execute(pool)
        .await?;

        let suspended_lookup = lookup(6);
        create(
            &repository,
            principal,
            Uuid::new_v4(),
            SessionKind::Cli,
            suspended_lookup.clone(),
            1,
        )
        .await?;
        sqlx::query(
            "UPDATE tenant_human_memberships SET status='suspended',suspended_at_ms=180000,suspended_reason='test',updated_at_ms=180000,revision=revision+1 WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(TENANT)
        .bind(principal)
        .execute(pool)
        .await?;
        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    suspended_lookup,
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::MembershipSuspended
        );
        sqlx::query(
            "UPDATE tenant_human_memberships SET status='active',suspended_at_ms=NULL,suspended_reason=NULL,updated_at_ms=200000,revision=revision+1 WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(TENANT)
        .bind(principal)
        .execute(pool)
        .await?;
        let current_revision: i64 = sqlx::query_scalar(
            "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(TENANT)
        .bind(principal)
        .fetch_one(pool)
        .await?;
        let stale_lookup = lookup(7);
        create(
            &repository,
            principal,
            Uuid::new_v4(),
            SessionKind::Cli,
            stale_lookup.clone(),
            u64::try_from(current_revision)?,
        )
        .await?;
        sqlx::query(
            "UPDATE tenant_human_memberships SET authorization_revision=authorization_revision+1 WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(TENANT)
        .bind(principal)
        .execute(pool)
        .await?;
        assert_eq!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    stale_lookup,
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::AuthorizationRevisionChanged {
                session_revision: u64::try_from(current_revision)?,
                current_revision: u64::try_from(current_revision + 1)?,
            }
        );
        Ok(())
    })
    .await
}
