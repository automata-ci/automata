use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use automata_ci_auth::{
    human::{PrincipalId, ProviderId, ProviderSubject, TenantId},
    login::{
        ConsumeLoginTransaction, ConsumeLoginTransactionOutcome, CreateLoginTransactionOutcome,
        LoadLoginTransactionOutcome, LoginBindingDigest, LoginBindingDigestKeyId, LoginTransaction,
        LoginTransactionAccess, LoginTransactionBinding, LoginTransactionFlow, LoginTransactionId,
        LoginTransactionPurpose, LoginTransactionRepository, LoginTransactionState,
        LoginTransactionVersion, ReplaceLoginTransactionOutcome, ReplaceLoginTransactionState,
    },
    secret::{SecretBytes as AuthSecretBytes, SecretString},
    session::{
        ActivateCliSession, ActivateCliSessionOutcome, CreateSession, CreateSessionOutcome,
        DurableSession, DurableSessionIdentity, HumanSessionRepository, ResolveSession,
        ResolveSessionOutcome, RevokeOwnSession, RevokeOwnSessionOutcome, RevokePrincipalSessions,
        SessionId, SessionKind, SessionTokenDigest, SessionTokenDigestKeyId, SessionTokenLookup,
        TouchSession, TouchSessionOutcome,
    },
    time::UnixTimestamp,
};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::auth::{
    PostgresHumanSessionRepository, PostgresLoginTransactionRepository,
};
use automata_ci_postgres::test_support::TestClock;
use sqlx::PgPool;
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

fn now() -> UnixTimestamp {
    UnixTimestamp::from_seconds(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_secs(),
    )
}

fn keyring() -> Arc<LocalAes256GcmKeyring> {
    let material = LocalKeyMaterial::new(
        KeyId::new("login-kek-v1").expect("key ID"),
        SecretBytes::new(vec![0x42; 32]).expect("key bytes"),
    )
    .expect("key material");
    Arc::new(LocalAes256GcmKeyring::new(material, Vec::new(), []).expect("keyring"))
}

fn binding(name: &str, byte: u8) -> LoginTransactionBinding {
    LoginTransactionBinding::new(
        LoginBindingDigestKeyId::new(name).expect("binding key ID"),
        LoginBindingDigest::new([byte; 32]),
    )
}

fn browser_access(
    id: &str,
    tenant: &str,
    state_byte: u8,
    client_byte: u8,
) -> LoginTransactionAccess {
    LoginTransactionAccess::browser(
        LoginTransactionId::new(id).expect("login ID"),
        LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new(tenant).expect("tenant ID"),
        },
        ProviderId::new("github").expect("provider ID"),
        binding("oauth-state-v1", state_byte),
        binding("browser-cookie-v1", client_byte),
    )
    .expect("browser access")
}

fn browser_transaction(
    id: &str,
    tenant: &str,
    state_byte: u8,
    client_byte: u8,
    plaintext: &[u8],
    expires_at: u64,
) -> LoginTransaction {
    let created_at = now();
    LoginTransaction::new(
        LoginTransactionId::new(id).expect("login ID"),
        LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new(tenant).expect("tenant ID"),
        },
        ProviderId::new("github").expect("provider ID"),
        LoginTransactionFlow::browser(
            binding("oauth-state-v1", state_byte),
            binding("browser-cookie-v1", client_byte),
        )
        .expect("browser flow"),
        None,
        LoginTransactionState::new(
            AuthSecretBytes::new(plaintext.to_vec()).expect("provider state"),
        ),
        created_at,
        created_at
            .checked_add(expires_at.checked_sub(100).expect("test lifetime"))
            .expect("login expiry"),
    )
    .expect("login transaction")
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn login_transactions_encrypt_cas_and_consume_exactly_once_across_replicas() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(database.pool(), "tenant-a").await?;
        seed_tenant(database.pool(), "tenant-b").await?;
        let repository = Arc::new(PostgresLoginTransactionRepository::new(
            database.pool().clone(),
            keyring(),
        ));
        let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        assert_eq!(
            repository
                .create(browser_transaction(
                    id,
                    "tenant-a",
                    1,
                    2,
                    b"provider-state-v1",
                    700,
                ))
                .await?,
            CreateLoginTransactionOutcome::Created(
                LoginTransactionVersion::new(1).expect("version")
            )
        );

        let stored: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT encrypted_payload, state_hash, browser_binding_hash, wrapped_data_key FROM human_login_transactions WHERE id=$1",
        )
        .bind(Uuid::parse_str(id)?)
        .fetch_one(database.pool())
        .await?;
        assert!(!stored.0.windows(17).any(|window| window == b"provider-state-v1"));
        assert_eq!(stored.1, vec![1; 32]);
        assert_eq!(stored.2, vec![2; 32]);
        assert_ne!(stored.3, b"provider-state-v1");

        let access = browser_access(id, "tenant-a", 1, 2);
        let LoadLoginTransactionOutcome::Active(loaded) = repository
            .load(&access, now())
            .await?
        else {
            panic!("transaction should load")
        };
        assert_eq!(loaded.transaction().state().expose_secret(), b"provider-state-v1");
        assert!(matches!(
            repository
                .load(
                    &browser_access(id, "tenant-a", 1, 3),
                    now()
                )
                .await?,
            LoadLoginTransactionOutcome::NotFound
        ));

        let replacement = ReplaceLoginTransactionState::new(
            access.clone(),
            loaded.version(),
            LoginTransactionState::new(
                AuthSecretBytes::new(b"provider-state-v2".to_vec()).expect("state"),
            ),
        );
        assert_eq!(
            repository
                .replace_state(replacement, now())
                .await?,
            ReplaceLoginTransactionOutcome::Replaced(
                LoginTransactionVersion::new(2).expect("version")
            )
        );
        assert_eq!(
            repository
                .replace_state(
                    ReplaceLoginTransactionState::new(
                        access.clone(),
                        LoginTransactionVersion::new(1).expect("version"),
                        LoginTransactionState::new(
                            AuthSecretBytes::new(b"stale".to_vec()).expect("state"),
                        ),
                    ),
                    now(),
                )
                .await?,
            ReplaceLoginTransactionOutcome::VersionConflict
        );

        let copied_id = "abababab-abab-4bab-8bab-abababababab";
        repository
            .create(browser_transaction(
                copied_id,
                "tenant-b",
                11,
                12,
                b"unrelated-state",
                700,
            ))
            .await?;
        sqlx::query(
            r"
            UPDATE human_login_transactions AS target
            SET (encrypted_payload, payload_nonce, wrapped_data_key,
                 encryption_key_id, encryption_schema) = (
                SELECT encrypted_payload, payload_nonce, wrapped_data_key,
                       encryption_key_id, encryption_schema
                FROM human_login_transactions WHERE id=$1
            ),
                revision=target.revision+1
            WHERE target.id=$2
            ",
        )
        .bind(Uuid::parse_str(id)?)
        .bind(Uuid::parse_str(copied_id)?)
        .execute(database.pool())
        .await?;
        let copied_access = browser_access(copied_id, "tenant-b", 11, 12);
        assert_eq!(
            repository
                .load(&copied_access, now())
                .await
                .expect_err("copied ciphertext must fail exact tenant/row AAD"),
            automata_ci_auth::login::LoginTransactionRepositoryError::IntegrityFailure
        );

        let first_repository = Arc::clone(&repository);
        let second_repository = Arc::clone(&repository);
        let first_request = ConsumeLoginTransaction::new(
            access.clone(),
            now(),
        )
        .if_version(LoginTransactionVersion::new(2).expect("version"));
        let second_request = first_request.clone();
        let (first, second) = tokio::join!(
            first_repository.consume(first_request),
            second_repository.consume(second_request)
        );
        let outcomes = [first?, second?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ConsumeLoginTransactionOutcome::Consumed(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ConsumeLoginTransactionOutcome::AlreadyConsumed))
                .count(),
            1
        );
        // A process crash or provider-exchange failure after consumption cannot
        // restart the exchange with the same provider state.
        assert!(matches!(
            repository
                .consume(ConsumeLoginTransaction::new(
                    access,
                    now()
                ))
                .await?,
            ConsumeLoginTransactionOutcome::AlreadyConsumed
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn setup_and_expired_login_transactions_preserve_purpose_and_tenant_boundaries() -> TestResult
{
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(database.pool(), "tenant-a").await?;
        let repository =
            PostgresLoginTransactionRepository::new(database.pool().clone(), keyring());
        let id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let poll = binding("device-poll-v1", 4);
        let created_at = now();
        let transaction = LoginTransaction::new(
            LoginTransactionId::new(id).expect("login ID"),
            LoginTransactionPurpose::InstallationSetup,
            ProviderId::new("github").expect("provider ID"),
            LoginTransactionFlow::device(
                poll.clone(),
                SecretString::new("ABCD-EFGH").expect("user code"),
                "https://github.com/login/device",
                5_000,
                created_at.checked_add(1).expect("next poll"),
            )?,
            None,
            LoginTransactionState::new(
                AuthSecretBytes::new(b"device-code".to_vec()).expect("state"),
            ),
            created_at,
            created_at.checked_add(2).expect("login expiry"),
        )?;
        repository.create(transaction).await?;
        let access = LoginTransactionAccess::device(
            LoginTransactionId::new(id).expect("login ID"),
            LoginTransactionPurpose::InstallationSetup,
            ProviderId::new("github").expect("provider ID"),
            poll,
        );
        let LoadLoginTransactionOutcome::Active(loaded) = repository
            .load(&access, now())
            .await?
        else {
            panic!("setup transaction should load")
        };
        assert_eq!(loaded.transaction().tenant_id(), None);
        let encrypted_payload: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_payload FROM human_login_transactions WHERE id=$1",
        )
        .bind(Uuid::parse_str(id)?)
        .fetch_one(database.pool())
        .await?;
        assert!(!encrypted_payload
            .windows(b"ABCD-EFGH".len())
            .any(|window| window == b"ABCD-EFGH"));
        assert!(!encrypted_payload
            .windows(b"github.com/login/device".len())
            .any(|window| window == b"github.com/login/device"));
        let forbidden_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema=current_schema()
              AND table_name='human_login_transactions'
              AND column_name IN ('device_user_code','verification_uri','device_code','pkce_verifier')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(forbidden_columns, 0);
        let expires_at_ms: i64 = sqlx::query_scalar(
            "SELECT expires_at_ms FROM human_login_transactions WHERE id=$1",
        )
        .bind(Uuid::parse_str(id)?)
        .fetch_one(database.pool())
        .await?;
        clock.set(expires_at_ms).await?;
        assert!(matches!(
            repository
                .load(&access, now())
                .await?,
            LoadLoginTransactionOutcome::Expired
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn schema_uses_canonical_permissions_and_bumps_membership_authorization_revision()
-> TestResult {
    run_with_database(|database| async move {
        seed_tenant(database.pool(), "tenant-a").await?;
        let principal = seed_human(database.pool(), "tenant-a").await?;
        let permission_count: i64 = sqlx::query_scalar("SELECT count(*) FROM rbac_permissions")
            .fetch_one(database.pool())
            .await?;
        let dotted_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rbac_permissions WHERE position('.' IN name) > 0",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(permission_count, 52);
        assert_eq!(dotted_count, 0);

        let role = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO rbac_roles (tenant_id,id,name,display_name,created_at_ms,updated_at_ms) VALUES ('tenant-a',$1,'viewer','Viewer',100000,100000)",
        )
        .bind(role)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO rbac_role_bindings (tenant_id,id,principal_id,role_id,scope_kind,created_at_ms) VALUES ('tenant-a',$1,$2,$3,'tenant',100000)",
        )
        .bind(Uuid::new_v4())
        .bind(principal)
        .bind(role)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO rbac_role_permissions (tenant_id,role_id,permission_name,granted_at_ms) VALUES ('tenant-a',$1,'runs:read',100000)",
        )
        .bind(role)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_role_mappings (
                tenant_id,id,organization_id,organization_login,role_id,
                scope_kind,created_at_ms,updated_at_ms
            ) VALUES ('tenant-a',$1,42,'automata-ci',$2,'tenant',100000,100000)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(role)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended', suspended_at_ms=110000,
                suspended_reason='test', revision=revision+1, updated_at_ms=110000
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(principal)
        .execute(database.pool())
        .await?;
        let revision: i64 = sqlx::query_scalar(
            "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id='tenant-a' AND principal_id=$1",
        )
        .bind(principal)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(revision, 5);

        let forbidden_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema=current_schema()
              AND (
                  (table_name='human_login_transactions' AND column_name IN (
                      'device_user_code','verification_uri','device_code','pkce_verifier'
                  ))
                  OR (table_name='security_audit_events' AND column_name='metadata')
              )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(forbidden_columns, 0);
        Ok(())
    })
    .await
}

fn session_lookup(key: &str, byte: u8) -> SessionTokenLookup {
    SessionTokenLookup::new(
        SessionTokenDigestKeyId::new(key).expect("digest key ID"),
        SessionTokenDigest::new([byte; 32]),
    )
}

fn durable_session(
    id: &str,
    tenant: &str,
    principal: Uuid,
    kind: SessionKind,
    revision: u64,
    idle_expires_at: u64,
) -> DurableSession {
    let issued_at = now();
    DurableSession::new(
        DurableSessionIdentity::new(
            SessionId::new(id).expect("session ID"),
            TenantId::new(tenant).expect("tenant ID"),
            PrincipalId::new(principal.hyphenated().to_string()).expect("principal ID"),
            ProviderId::new("github").expect("provider ID"),
            ProviderSubject::new("42").expect("provider subject"),
            kind,
        )
        .expect("identity"),
        revision,
        issued_at,
        issued_at,
        issued_at
            .checked_add(idle_expires_at.checked_sub(100).expect("idle lifetime"))
            .expect("idle expiry"),
        issued_at.checked_add(300).expect("absolute expiry"),
        None,
    )
    .expect("session")
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn touch_final_write_cannot_extend_a_session_expired_during_statement_delay() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        seed_tenant(pool, "tenant-a").await?;
        let principal = seed_human(pool, "tenant-a").await?;
        let repository = PostgresHumanSessionRepository::new(pool.clone());
        let session_id = "abababab-abab-4bab-8bab-abababababab";
        let lookup = session_lookup("touch-delay-hmac-v1", 0x5a);
        assert_eq!(
            repository
                .create(CreateSession::new(
                    lookup.clone(),
                    durable_session(
                        session_id,
                        "tenant-a",
                        principal,
                        SessionKind::Browser,
                        1,
                        102,
                    ),
                ))
                .await?,
            CreateSessionOutcome::Created
        );
        let before: (i64, i64) =
            sqlx::query_as("SELECT last_seen_at_ms,revision FROM human_sessions WHERE id=$1")
                .bind(Uuid::parse_str(session_id)?)
                .fetch_one(pool)
                .await?;
        let idle_expires_at_ms: i64 =
            sqlx::query_scalar("SELECT idle_expires_at_ms FROM human_sessions WHERE id=$1")
                .bind(Uuid::parse_str(session_id)?)
                .fetch_one(pool)
                .await?;
        sqlx::query(
            r"
            CREATE FUNCTION advance_session_touch_test_clock() RETURNS trigger AS $$
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
            CREATE TRIGGER advance_session_touch_test_clock
            BEFORE UPDATE ON human_sessions
            FOR EACH STATEMENT EXECUTE FUNCTION advance_session_touch_test_clock()
            ",
        )
        .execute(pool)
        .await?;
        clock
            .set(
                idle_expires_at_ms
                    .checked_sub(1)
                    .expect("time immediately before idle expiry"),
            )
            .await?;
        let observed_at = now();
        assert_eq!(
            repository
                .touch(&TouchSession::new(
                    lookup,
                    SessionKind::Browser,
                    observed_at,
                    observed_at.checked_add(100)?,
                )?)
                .await?,
            TouchSessionOutcome::Expired
        );
        let after: (i64, i64) =
            sqlx::query_as("SELECT last_seen_at_ms,revision FROM human_sessions WHERE id=$1")
                .bind(Uuid::parse_str(session_id)?)
                .fetch_one(pool)
                .await?;
        assert_eq!(after, before);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn sessions_enforce_audience_idle_revision_and_tenant_scoped_revocation() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(database.pool(), "tenant-a").await?;
        seed_tenant(database.pool(), "tenant-b").await?;
        let principal = seed_human(database.pool(), "tenant-a").await?;
        seed_membership(database.pool(), "tenant-b", principal).await?;
        let repository = PostgresHumanSessionRepository::new(database.pool().clone());

        let first_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let first_lookup = session_lookup("session-hmac-v1", 5);
        assert_eq!(
            repository
                .create(CreateSession::new(
                    first_lookup.clone(),
                    durable_session(first_id, "tenant-a", principal, SessionKind::Browser, 1, 200),
                ))
                .await?,
            CreateSessionOutcome::Created
        );
        assert!(matches!(
            repository
                .resolve(&ResolveSession::new(
                    first_lookup.clone(),
                    SessionKind::Browser,
                    now(),
                ))
                .await?,
            ResolveSessionOutcome::Active(_)
        ));
        assert!(matches!(
            repository
                .resolve(&ResolveSession::new(
                    first_lookup.clone(),
                    SessionKind::Cli,
                    now(),
                ))
                .await?,
            ResolveSessionOutcome::WrongKindOrAudience
        ));
        sqlx::query(
            "UPDATE tenant_human_memberships SET authorization_revision=authorization_revision+1 WHERE tenant_id='tenant-a' AND principal_id=$1",
        )
        .bind(principal)
        .execute(database.pool())
        .await?;
        assert!(matches!(
            repository
                .resolve(&ResolveSession::new(
                    first_lookup.clone(),
                    SessionKind::Browser,
                    now(),
                ))
                .await?,
            ResolveSessionOutcome::AuthorizationRevisionChanged {
                session_revision: 1,
                current_revision: 2
            }
        ));
        sqlx::query("UPDATE human_sessions SET authorization_revision=2 WHERE id=$1")
            .bind(Uuid::parse_str(first_id)?)
            .execute(database.pool())
            .await?;
        clock.advance(1_100).await?;
        sqlx::query(
            r"
            UPDATE human_sessions
            SET idle_expires_at_ms =
                floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000
            WHERE id=$1
            ",
        )
        .bind(Uuid::parse_str(first_id)?)
        .execute(database.pool())
        .await?;
        assert!(matches!(
            repository
                .resolve(&ResolveSession::new(
                    first_lookup.clone(),
                    SessionKind::Browser,
                    now(),
                ))
                .await?,
            ResolveSessionOutcome::Expired
        ));

        let second_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        let second_lookup = session_lookup("session-hmac-v1", 6);
        repository
            .create(CreateSession::new(
                second_lookup.clone(),
                durable_session(second_id, "tenant-a", principal, SessionKind::Browser, 2, 220),
            ))
            .await?;
        clock.advance(1_100).await?;
        assert!(matches!(
            repository
                .touch(&TouchSession::new(
                    second_lookup.clone(),
                    SessionKind::Browser,
                    now(),
                    now().checked_add(100)?,
                )?)
                .await?,
            TouchSessionOutcome::Touched(_)
        ));

        let principal_id = PrincipalId::new(principal.hyphenated().to_string())?;
        assert_eq!(
            repository
                .revoke_own(&RevokeOwnSession::new(
                    TenantId::new("tenant-b")?,
                    principal_id.clone(),
                    SessionId::new(second_id)?,
                    now(),
                ))
                .await?,
            RevokeOwnSessionOutcome::NotFound
        );
        assert_eq!(
            repository
                .revoke_own(&RevokeOwnSession::new(
                    TenantId::new("tenant-a")?,
                    principal_id.clone(),
                    SessionId::new(second_id)?,
                    now(),
                ))
                .await?,
            RevokeOwnSessionOutcome::Revoked
        );
        assert!(matches!(
            repository
                .resolve(&ResolveSession::new(
                    second_lookup,
                    SessionKind::Browser,
                    now(),
                ))
                .await?,
            ResolveSessionOutcome::Revoked
        ));

        let tenant_b_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let tenant_b_lookup = session_lookup("session-hmac-v1", 7);
        repository
            .create(CreateSession::new(
                tenant_b_lookup.clone(),
                durable_session(tenant_b_id, "tenant-b", principal, SessionKind::Cli, 1, 250),
            ))
            .await?;
        assert!(matches!(
            repository
                .resolve(&ResolveSession::new(
                    tenant_b_lookup.clone(),
                    SessionKind::Cli,
                    now(),
                ))
                .await?,
            ResolveSessionOutcome::NotYetValid
        ));
        assert!(matches!(
            repository
                .touch(&TouchSession::new(
                    tenant_b_lookup.clone(),
                    SessionKind::Cli,
                    now(),
                    now().checked_add(90)?,
                )?)
                .await?,
            TouchSessionOutcome::NotYetValid
        ));
        assert!(matches!(
            repository
                .activate_cli(&ActivateCliSession::new(
                    tenant_b_lookup.clone(),
                    now(),
                ))
                .await?,
            ActivateCliSessionOutcome::Activated(_)
        ));
        assert_eq!(
            repository
                .revoke_principal(&RevokePrincipalSessions::new(
                    TenantId::new("tenant-a")?,
                    principal_id,
                    now(),
                ))
                .await?
                .revoked_sessions(),
            1
        );
        assert!(matches!(
            repository
                .resolve(&ResolveSession::new(
                    tenant_b_lookup,
                    SessionKind::Cli,
                    now(),
                ))
                .await?,
            ResolveSessionOutcome::Active(_)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn principal_revocation_fails_closed_instead_of_leaving_future_issued_sessions() -> TestResult
{
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool, "tenant-a").await?;
        let principal = seed_human(pool, "tenant-a").await?;
        let repository = PostgresHumanSessionRepository::new(pool.clone());
        let current_id = "12121212-1212-4212-8212-121212121212";
        repository
            .create(CreateSession::new(
                session_lookup("session-hmac-v1", 0x31),
                durable_session(
                    current_id,
                    "tenant-a",
                    principal,
                    SessionKind::Browser,
                    1,
                    200,
                ),
            ))
            .await?;
        let future_id = Uuid::parse_str("34343434-3434-4434-8434-343434343434")?;
        sqlx::query(
            r"
            INSERT INTO human_sessions (
                id,tenant_id,principal_id,provider_id,provider_subject,
                session_kind,audience,token_hash,token_hash_key_id,
                authorization_revision,issued_at_ms,last_seen_at_ms,
                idle_expires_at_ms,expires_at_ms
            ) VALUES ($1,'tenant-a',$2,'github','42','browser','automata.web',
                      $3,'session-hmac-v1',1,
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 30000,
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 30000,
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 500000,
                      floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 600000)
            ",
        )
        .bind(future_id)
        .bind(principal)
        .bind(vec![0x32_u8; 32])
        .execute(pool)
        .await?;

        assert_eq!(
            repository
                .revoke_principal(&RevokePrincipalSessions::new(
                    TenantId::new("tenant-a")?,
                    PrincipalId::new(principal.hyphenated().to_string())?,
                    now(),
                ))
                .await
                .expect_err("future-issued rows must not be silently skipped"),
            automata_ci_auth::session::SessionRepositoryError::CorruptData
        );
        let revoked: Vec<Option<i64>> = sqlx::query_scalar(
            "SELECT revoked_at_ms FROM human_sessions WHERE tenant_id='tenant-a' ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
        assert_eq!(revoked, vec![None, None]);
        Ok(())
    })
    .await
}

async fn seed_tenant(pool: &PgPool, tenant: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1,$1,100000,100000)",
    )
    .bind(tenant)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_human(pool: &PgPool, tenant: &str) -> TestResult<Uuid> {
    let principal = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO human_principals (id, created_at_ms, updated_at_ms) VALUES ($1,100000,100000)",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id, provider_id, provider_subject, provider_login,
            normalized_login, first_authenticated_at_ms, last_authenticated_at_ms,
            last_observed_at_ms, created_at_ms, updated_at_ms
        ) VALUES ($1,'github','42','octocat','octocat',100000,100000,100000,100000,100000)
        ",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    seed_membership(pool, tenant, principal).await?;
    Ok(principal)
}

async fn seed_membership(pool: &PgPool, tenant: &str, principal: Uuid) -> TestResult {
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1,$2,100000,100000)",
    )
    .bind(tenant)
    .bind(principal)
    .execute(pool)
    .await?;
    Ok(())
}
