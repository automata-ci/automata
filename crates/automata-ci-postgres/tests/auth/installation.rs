use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::support::{TestResult, run_with_database};
use automata_ci_auth::{
    github::{
        GithubMembershipObservation, GithubMembershipSnapshot, GithubMembershipSnapshotId,
        GithubOrganizationId, GithubOrganizationLogin, GithubOrganizationMembership,
        GithubOrganizationMembershipRole,
    },
    human::{ProviderId, ProviderIdentityAssertion, ProviderSubject, TenantId},
    installation::{
        ArmInstallationSetup, BindInstallationLogin, CompleteInstallationOutcome,
        CompleteInstallationSetup, InstallationProof, InstallationProofDigest,
        InstallationProofKeyId, InstallationProviderAuthentication, InstallationRepository,
        InstallationRepositoryError, InstallationRevision, InstallationState, InstallationTenant,
    },
    login::{
        ConsumeLoginTransaction, ConsumeLoginTransactionOutcome, LoginBindingDigest,
        LoginBindingDigestKeyId, LoginTransaction, LoginTransactionAccess, LoginTransactionBinding,
        LoginTransactionFlow, LoginTransactionId, LoginTransactionPurpose,
        LoginTransactionRepository, LoginTransactionState,
    },
    secret::{SecretBytes as AuthSecretBytes, SecretString, SystemSecureRandom},
    session::{SessionKind, SessionTokenDigestKeyId},
    session_credential::{
        SessionCredentialKey, SessionCredentialKeyring, SessionCredentialService,
    },
    sign_in::PendingSessionCandidate,
    time::{Clock, UnixTimestamp},
    vault::{
        ProviderAccessToken, ProviderGrantKind, ProviderRefreshToken, ProviderTokenKey,
        ProviderTokenMetadata, ProviderTokenSet, ProviderTokenVault,
    },
};
use automata_ci_key_management::{
    KeyEncryptionContext, KeyEncryptionError, KeyEncryptionProvider, WrappedDataKey,
};
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres::auth::{
    PostgresHumanSessionRepository, PostgresInstallationRepository,
    PostgresLoginTransactionRepository, PostgresProviderTokenVault,
};
use automata_ci_postgres::test_support::TestClock;
use uuid::Uuid;

const LOGIN_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const ACCESS_A: &str = "bootstrap-provider-access-sentinel-a";
const ACCESS_B: &str = "bootstrap-provider-access-sentinel-b";
const REFRESH_A: &str = "bootstrap-provider-refresh-sentinel-a";
const REFRESH_B: &str = "bootstrap-provider-refresh-sentinel-b";
const RETRY_LOGIN_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const REBIND_FIRST_LOGIN_ID: &str = "11111111-1111-4111-8111-111111111111";
const REBIND_SECOND_LOGIN_ID: &str = "22222222-2222-4222-8222-222222222222";
const SESSION_KEY_ID: &str = "bootstrap-session-hmac-v1";
const SCENARIO_REFERENCE_SECONDS: u64 = 150;

fn scenario_time(seconds: u64) -> UnixTimestamp {
    let current = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_secs();
    let rebased = if seconds >= SCENARIO_REFERENCE_SECONDS {
        current.checked_add(seconds - SCENARIO_REFERENCE_SECONDS)
    } else {
        current.checked_sub(SCENARIO_REFERENCE_SECONDS - seconds)
    }
    .expect("scenario time");
    UnixTimestamp::from_seconds(rebased)
}

#[derive(Debug)]
struct FixedClock(UnixTimestamp);

impl Clock for FixedClock {
    fn now(&self) -> UnixTimestamp {
        self.0
    }
}

#[derive(Debug)]
struct UnavailableKeyProvider;

#[async_trait::async_trait]
impl KeyEncryptionProvider for UnavailableKeyProvider {
    async fn wrap_data_key(
        &self,
        _plaintext_key: &SecretBytes,
        _context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        Err(KeyEncryptionError::Unavailable)
    }

    async fn unwrap_data_key(
        &self,
        _wrapped_key: &WrappedDataKey,
        _context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        Err(KeyEncryptionError::Unavailable)
    }
}

fn keyring() -> Arc<LocalAes256GcmKeyring> {
    let material = LocalKeyMaterial::new(
        KeyId::new("bootstrap-kek-v1").expect("key ID"),
        SecretBytes::new(vec![0x73; 32]).expect("key bytes"),
    )
    .expect("key material");
    Arc::new(LocalAes256GcmKeyring::new(material, Vec::new(), []).expect("keyring"))
}

fn proof(byte: u8) -> InstallationProof {
    InstallationProof::new(
        InstallationProofKeyId::new("bootstrap-proof-v1").expect("proof key ID"),
        InstallationProofDigest::new([byte; 32]),
    )
}

fn binding(key_id: &str, byte: u8) -> LoginTransactionBinding {
    LoginTransactionBinding::new(
        LoginBindingDigestKeyId::new(key_id).expect("binding key ID"),
        LoginBindingDigest::new([byte; 32]),
    )
}

fn login_transaction(
    id: &str,
    state_byte: u8,
    created_at: u64,
    expires_at: u64,
) -> (LoginTransaction, LoginTransactionAccess) {
    let state = binding("setup-oauth-state-v1", state_byte);
    let client = binding("setup-browser-binding-v1", state_byte.wrapping_add(1));
    let login_id = LoginTransactionId::new(id).expect("login transaction ID");
    let purpose = LoginTransactionPurpose::InstallationSetup;
    let provider = ProviderId::new("github").expect("provider");
    let transaction = LoginTransaction::new(
        login_id.clone(),
        purpose.clone(),
        provider.clone(),
        LoginTransactionFlow::browser(state.clone(), client.clone()).expect("browser flow"),
        None,
        LoginTransactionState::new(
            AuthSecretBytes::new(b"oauth-pkce-state-sentinel".to_vec()).expect("login state"),
        ),
        scenario_time(created_at),
        scenario_time(expires_at),
    )
    .expect("login transaction");
    let access = LoginTransactionAccess::browser(login_id, purpose, provider, state, client)
        .expect("login access");
    (transaction, access)
}

fn tenant() -> InstallationTenant {
    InstallationTenant::new(
        TenantId::new("bootstrap-tenant").expect("tenant"),
        "Bootstrap Tenant",
    )
    .expect("installation tenant")
}

fn identity_at(authenticated_at: UnixTimestamp) -> ProviderIdentityAssertion {
    ProviderIdentityAssertion::new(
        ProviderId::new("github").expect("provider"),
        ProviderSubject::new("424242").expect("subject"),
        "OctoCat",
        Some("The Octocat".to_owned()),
        authenticated_at,
    )
    .expect("provider identity")
}

fn tokens(access: &str, refresh: &str) -> ProviderTokenSet {
    let metadata = ProviderTokenMetadata::builder(
        ProviderId::new("github").expect("provider"),
        ProviderGrantKind::BrowserAuthorizationCode,
        "Bearer",
        scenario_time(135),
    )
    .scopes(BTreeSet::from(["read:org".to_owned(), "repo".to_owned()]))
    .access_expires_at(Some(scenario_time(1_000)))
    .refresh_expires_at(Some(scenario_time(10_000)))
    .build()
    .expect("provider metadata");
    ProviderTokenSet::new(
        ProviderAccessToken::new(SecretString::new(access).expect("access token")),
        Some(ProviderRefreshToken::new(
            SecretString::new(refresh).expect("refresh token"),
        )),
        metadata,
    )
    .expect("provider token set")
}

fn memberships() -> GithubMembershipSnapshot {
    GithubMembershipSnapshot::new(
        [GithubOrganizationMembership::new(
            GithubOrganizationId::new(101).expect("organization ID"),
            GithubOrganizationLogin::new("automata-ci").expect("organization login"),
            GithubOrganizationMembershipRole::Admin,
        )],
        [],
    )
    .expect("membership snapshot")
}

fn prepare_session_at(pool: &sqlx::PgPool, issued_at: UnixTimestamp) -> PendingSessionCandidate {
    let key = SessionCredentialKey::new(
        SessionTokenDigestKeyId::new(SESSION_KEY_ID).expect("session key ID"),
        AuthSecretBytes::new(vec![0x5a; 32]).expect("session key"),
    )
    .expect("session credential key");
    let service = SessionCredentialService::new(
        SessionCredentialKeyring::new(key, Vec::new()).expect("session keyring"),
        Arc::new(PostgresHumanSessionRepository::new(pool.clone())),
        Arc::new(SystemSecureRandom),
        Arc::new(FixedClock(issued_at)),
    );
    let prepared = service
        .prepare(
            SessionKind::Browser,
            Duration::from_mins(2),
            Duration::from_mins(10),
        )
        .expect("prepared bootstrap session");
    let (_credential, candidate) = prepared.into_parts();
    candidate
}

fn completion_for(
    pool: &sqlx::PgPool,
    id: &str,
    access: &str,
    refresh: &str,
) -> CompleteInstallationSetup {
    completion_for_at(pool, id, access, refresh, scenario_time(150))
}

fn completion_for_at(
    pool: &sqlx::PgPool,
    id: &str,
    access: &str,
    refresh: &str,
    completed_at: UnixTimestamp,
) -> CompleteInstallationSetup {
    let authentication = InstallationProviderAuthentication::new(
        LoginTransactionId::new(id).expect("login ID"),
        identity_at(completed_at),
        tokens(access, refresh),
        GithubMembershipObservation::new(
            GithubMembershipSnapshotId::new(id).expect("snapshot ID"),
            memberships(),
            completed_at,
            scenario_time(600),
        )
        .expect("membership observation"),
    )
    .expect("provider authentication");
    CompleteInstallationSetup::new(
        InstallationRevision::new(3).expect("installation revision"),
        tenant(),
        authentication,
        prepare_session_at(pool, completed_at),
        completed_at,
    )
    .expect("completion request")
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn database_now_minus_sixty_rolls_back_expired_bootstrap_authority() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        let whole_second_ms = clock
            .now()
            .await?
            .checked_add(999)
            .expect("whole-second database time")
            / 1_000
            * 1_000;
        clock.set(whole_second_ms).await?;
        let encryption = keyring();
        let installation = PostgresInstallationRepository::new(pool.clone(), encryption.clone());
        let login = PostgresLoginTransactionRepository::new(pool.clone(), encryption);
        let armed = installation
            .arm(ArmInstallationSetup::new(
                tenant(),
                proof(0x39),
                ProviderId::new("github")?,
                ProviderSubject::new("424242")?,
                scenario_time(100),
                scenario_time(600),
            )?)
            .await?;
        let (transaction, access) = login_transaction(LOGIN_ID, 0x39, 110, 500);
        login.create(transaction).await?;
        let bound = installation
            .bind_login(BindInstallationLogin::new(
                armed.revision(),
                proof(0x39),
                LoginTransactionId::new(LOGIN_ID)?,
                scenario_time(120),
            ))
            .await?;
        assert!(matches!(
            login
                .consume(ConsumeLoginTransaction::new(access, scenario_time(130)))
                .await?,
            ConsumeLoginTransactionOutcome::Consumed(_)
        ));

        let database_now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
                .fetch_one(pool)
                .await?;
        let database_now_ms = database_now
            .checked_mul(1_000)
            .expect("database milliseconds");
        // Model a setup login consumed before the accepted negative-skew
        // callback. Repository creation is deliberately rebased to database now,
        // so shift this fixture's immutable lifecycle as one coherent history.
        sqlx::query("ALTER TABLE human_login_transactions DISABLE TRIGGER USER")
            .execute(pool)
            .await?;
        sqlx::query(
            r"
            UPDATE human_login_transactions
            SET created_at_ms=$2-90000, consumed_at_ms=$2-80000,
                updated_at_ms=$2-80000
            WHERE id=$1
            ",
        )
        .bind(Uuid::parse_str(LOGIN_ID)?)
        .bind(database_now_ms)
        .execute(pool)
        .await?;
        sqlx::query("ALTER TABLE human_login_transactions ENABLE TRIGGER USER")
            .execute(pool)
            .await?;
        sqlx::query(
            "ALTER TABLE human_auth_installation_state DISABLE TRIGGER human_auth_installation_state_lifecycle_guard",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "UPDATE human_auth_installation_state SET updated_at_ms=$1-90000 WHERE singleton",
        )
        .bind(database_now_ms)
        .execute(pool)
        .await?;
        sqlx::query(
            "ALTER TABLE human_auth_installation_state ENABLE TRIGGER human_auth_installation_state_lifecycle_guard",
        )
        .execute(pool)
        .await?;
        let database_now = u64::try_from(database_now)?;
        let caller_now =
            UnixTimestamp::from_seconds(database_now.checked_sub(60).expect("caller timestamp"));
        let provider_expiry =
            UnixTimestamp::from_seconds(database_now.checked_sub(1).expect("provider expiry"));
        let authenticated_at = UnixTimestamp::from_seconds(
            caller_now
                .as_seconds()
                .checked_sub(10)
                .expect("identity time"),
        );
        let observed_at = UnixTimestamp::from_seconds(
            caller_now
                .as_seconds()
                .checked_sub(5)
                .expect("observation time"),
        );
        let metadata = ProviderTokenMetadata::builder(
            ProviderId::new("github")?,
            ProviderGrantKind::BrowserAuthorizationCode,
            "Bearer",
            UnixTimestamp::from_seconds(
                caller_now.as_seconds().checked_sub(20).expect("issue time"),
            ),
        )
        .scopes(BTreeSet::from(["read:org".to_owned(), "repo".to_owned()]))
        .access_expires_at(Some(provider_expiry))
        .refresh_expires_at(Some(UnixTimestamp::from_seconds(
            database_now.checked_add(600).expect("refresh expiry"),
        )))
        .build()?;
        let authentication = InstallationProviderAuthentication::new(
            LoginTransactionId::new(LOGIN_ID)?,
            ProviderIdentityAssertion::new(
                ProviderId::new("github")?,
                ProviderSubject::new("424242")?,
                "negative-skew-bootstrap",
                None,
                authenticated_at,
            )?,
            ProviderTokenSet::new(
                ProviderAccessToken::new(SecretString::new("negative-skew-access")?),
                Some(ProviderRefreshToken::new(SecretString::new(
                    "negative-skew-refresh",
                )?)),
                metadata,
            )?,
            GithubMembershipObservation::new(
                GithubMembershipSnapshotId::new(LOGIN_ID)?,
                memberships(),
                observed_at,
                provider_expiry,
            )?,
        )?;
        let request = CompleteInstallationSetup::new(
            bound.revision(),
            tenant(),
            authentication,
            prepare_session_at(pool, caller_now),
            caller_now,
        )?;
        assert_eq!(
            installation
                .complete(request)
                .await
                .expect_err("expired provider authority must not bootstrap"),
            InstallationRepositoryError::Expired
        );
        let rolled_back: (i64, i64, i64, i64, i64, i64, String, i64) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM tenants),
              (SELECT count(*) FROM human_principals),
              (SELECT count(*) FROM tenant_human_memberships),
              (SELECT count(*) FROM human_provider_tokens),
              (SELECT count(*) FROM human_sessions),
              (SELECT count(*) FROM rbac_role_bindings),
              (SELECT status FROM human_login_transactions WHERE id=$1),
              (SELECT revision FROM human_auth_installation_state WHERE singleton)
            ",
        )
        .bind(Uuid::parse_str(LOGIN_ID)?)
        .fetch_one(pool)
        .await?;
        assert_eq!(rolled_back, (0, 0, 0, 0, 0, 0, "consumed".to_owned(), 3));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn login_binding_final_write_rechecks_both_deadlines_after_statement_delay() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        let encryption = keyring();
        let installation =
            PostgresInstallationRepository::new(pool.clone(), encryption.clone());
        let login = PostgresLoginTransactionRepository::new(pool.clone(), encryption);
        let armed = installation
            .arm(ArmInstallationSetup::new(
                tenant(),
                proof(0x4a),
                ProviderId::new("github")?,
                ProviderSubject::new("424242")?,
                scenario_time(150),
                scenario_time(152),
        )?)
        .await?;
        let (transaction, _) = login_transaction(LOGIN_ID, 0x4a, 150, 152);
        login.create(transaction).await?;
        let final_deadline_ms: i64 = sqlx::query_scalar(
            r"
            SELECT LEAST(
                installation.challenge_expires_at_ms,
                login.expires_at_ms
            )
            FROM human_auth_installation_state AS installation
            JOIN human_login_transactions AS login ON login.id=$1
            WHERE installation.singleton
            ",
        )
        .bind(Uuid::parse_str(LOGIN_ID)?)
        .fetch_one(pool)
        .await?;
        clock
            .set(
                final_deadline_ms
                    .checked_sub(1)
                    .expect("time immediately before binding expiry"),
            )
            .await?;
        sqlx::query(
            r"
            CREATE FUNCTION advance_installation_binding_test_clock() RETURNS trigger AS $$
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
            CREATE TRIGGER advance_installation_binding_test_clock
            BEFORE UPDATE ON human_auth_installation_state
            FOR EACH STATEMENT EXECUTE FUNCTION advance_installation_binding_test_clock()
            ",
        )
        .execute(pool)
        .await?;
        assert_eq!(
            installation
                .bind_login(BindInstallationLogin::new(
                    armed.revision(),
                    proof(0x4a),
                    LoginTransactionId::new(LOGIN_ID)?,
                    scenario_time(150),
                ))
                .await
                .expect_err("expired binding must not be installed"),
            InstallationRepositoryError::Expired
        );
        let unchanged: (String, Option<Uuid>, i64) = sqlx::query_as(
            "SELECT state,setup_transaction_id,revision FROM human_auth_installation_state WHERE singleton",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(unchanged, ("pending".to_owned(), None, 2));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn active_arm_is_idempotent_for_exact_configuration_under_concurrency() -> TestResult {
    run_with_database(|database| async move {
        let installation = Arc::new(PostgresInstallationRepository::new(
            database.pool().clone(),
            keyring(),
        ));
        let arm = |proof_byte| {
            ArmInstallationSetup::new(
                tenant(),
                proof(proof_byte),
                ProviderId::new("github").expect("provider"),
                ProviderSubject::new("424242").expect("subject"),
                scenario_time(100),
                scenario_time(600),
            )
            .expect("arm request")
        };
        let first = Arc::clone(&installation);
        let second = Arc::clone(&installation);
        let (first, second) = tokio::join!(first.arm(arm(0x61)), second.arm(arm(0x61)));
        let first = first.expect("first exact arm");
        let second = second.expect("concurrent exact arm");
        assert_eq!(first, second);
        assert_eq!(
            first.revision(),
            InstallationRevision::new(2).expect("revision")
        );
        assert_eq!(
            installation.arm(arm(0x61)).await?,
            first,
            "an exact repeat must not advance the installation revision"
        );
        assert_eq!(
            installation
                .arm(arm(0x62))
                .await
                .expect_err("a different live proof must conflict"),
            InstallationRepositoryError::VersionConflict
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn exact_bound_login_replays_after_restart_and_a_different_login_fails_closed() -> TestResult
{
    run_with_database(|database| async move {
        let local_keyring = keyring();
        let installation =
            PostgresInstallationRepository::new(database.pool().clone(), local_keyring.clone());
        let login =
            PostgresLoginTransactionRepository::new(database.pool().clone(), local_keyring.clone());
        let armed = installation
            .arm(ArmInstallationSetup::new(
                tenant(),
                proof(0x51),
                ProviderId::new("github").expect("provider"),
                ProviderSubject::new("424242").expect("subject"),
                scenario_time(100),
                scenario_time(600),
            )?)
            .await?;
        let (first_login, _) = login_transaction(REBIND_FIRST_LOGIN_ID, 0x11, 110, 500);
        login.create(first_login).await?;
        let first_bound = installation
            .bind_login(BindInstallationLogin::new(
                armed.revision(),
                proof(0x51),
                LoginTransactionId::new(REBIND_FIRST_LOGIN_ID).expect("first login"),
                scenario_time(120),
            ))
            .await?;
        let InstallationState::LoginBound {
            revision,
            login_transaction_id,
            expires_at,
            ..
        } = &first_bound
        else {
            panic!("first setup login must be bound")
        };
        assert_eq!(*revision, InstallationRevision::new(3).expect("revision"));
        assert_eq!(login_transaction_id.as_str(), REBIND_FIRST_LOGIN_ID);
        let challenge_expiry_ms: i64 = sqlx::query_scalar(
            "SELECT challenge_expires_at_ms FROM human_auth_installation_state WHERE singleton",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            *expires_at,
            UnixTimestamp::from_seconds(u64::try_from(challenge_expiry_ms / 1000)?)
        );

        drop(installation);
        let restarted =
            PostgresInstallationRepository::new(database.pool().clone(), local_keyring.clone());
        let (second_login, _) = login_transaction(REBIND_SECOND_LOGIN_ID, 0x21, 130, 300);
        login.create(second_login).await?;
        assert_eq!(
            restarted
                .bind_login(BindInstallationLogin::new(
                    first_bound.revision(),
                    proof(0x51),
                    LoginTransactionId::new(REBIND_SECOND_LOGIN_ID).expect("second login"),
                    scenario_time(140),
                ))
                .await
                .expect_err("a different login must not replace the bound transaction"),
            InstallationRepositoryError::AlreadyBound
        );
        assert_eq!(
            restarted
                .bind_login(BindInstallationLogin::new(
                    armed.revision(),
                    proof(0x51),
                    LoginTransactionId::new(REBIND_FIRST_LOGIN_ID).expect("first login"),
                    scenario_time(150),
                ))
                .await?,
            first_bound,
            "the original predecessor must recover a committed bind after response loss"
        );
        sqlx::query("ALTER TABLE human_login_transactions DISABLE TRIGGER USER")
            .execute(database.pool())
            .await?;
        sqlx::query("UPDATE human_login_transactions SET provider_id='gitlab' WHERE id=$1")
            .bind(Uuid::parse_str(REBIND_FIRST_LOGIN_ID)?)
            .execute(database.pool())
            .await?;
        assert_eq!(
            restarted
                .bind_login(BindInstallationLogin::new(
                    armed.revision(),
                    proof(0x51),
                    LoginTransactionId::new(REBIND_FIRST_LOGIN_ID).expect("first login"),
                    scenario_time(150),
                ))
                .await
                .expect_err("a replay must revalidate immutable locked login evidence"),
            InstallationRepositoryError::CorruptData
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn bootstrap_is_proof_bound_atomic_encrypted_and_exactly_once() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let keyring = keyring();
        let installation = Arc::new(PostgresInstallationRepository::new(
            database.pool().clone(),
            keyring.clone(),
        ));
        let login =
            PostgresLoginTransactionRepository::new(database.pool().clone(), keyring.clone());
        assert!(matches!(
            installation
                .load()
                .await
                .expect("initial installation state"),
            InstallationState::Unconfigured { revision }
                if revision == InstallationRevision::new(1).expect("revision")
        ));
        let (too_early, _) =
            login_transaction("dddddddd-dddd-4ddd-8ddd-dddddddddddd", 0x21, 90, 500);
        login.create(too_early).await.expect("create pre-arm login");
        clock.advance(1_100).await?;

        let armed = installation
            .arm(ArmInstallationSetup::new(
                tenant(),
                proof(0x71),
                ProviderId::new("github").expect("provider"),
                ProviderSubject::new("424242").expect("subject"),
                scenario_time(100),
                scenario_time(600),
            )?)
            .await
            .expect("arm installation");
        let InstallationState::Armed { revision, .. } = armed else {
            panic!("setup must be armed")
        };
        assert_eq!(revision, InstallationRevision::new(2).expect("revision"));

        let direct_rewrite = sqlx::query(
            r"
            UPDATE human_auth_installation_state
            SET expected_provider_subject='substituted',
                updated_at_ms=human_auth_installation_state.updated_at_ms,
                revision=revision+1
            ",
        )
        .execute(database.pool())
        .await
        .expect_err("live pending setup metadata is immutable");
        assert_eq!(
            direct_rewrite
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("human_auth_installation_state_pending_exact")
        );
        let direct_early_bind = sqlx::query(
            r"
            UPDATE human_auth_installation_state
            SET setup_transaction_id=$1,
                updated_at_ms=floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000,
                revision=revision+1
            ",
        )
        .bind(Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd")?)
        .execute(database.pool())
        .await
        .expect_err("a pre-arm login cannot be bound through direct SQL");
        assert_eq!(
            direct_early_bind
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("human_auth_installation_state_bind_exact")
        );
        assert_eq!(
            installation
                .bind_login(BindInstallationLogin::new(
                    revision,
                    proof(0x71),
                    LoginTransactionId::new("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("login"),
                    scenario_time(120),
                ))
                .await
                .expect_err("pre-arm login cannot be bound"),
            InstallationRepositoryError::InvalidRequest
        );
        assert_eq!(
            installation
                .bind_login(BindInstallationLogin::new(
                    revision,
                    proof(0x72),
                    LoginTransactionId::new(LOGIN_ID).expect("login"),
                    scenario_time(120),
                ))
                .await
                .expect_err("wrong proof must fail before lookup"),
            InstallationRepositoryError::ProofRejected
        );

        let (transaction, access) = login_transaction(LOGIN_ID, 0x31, 110, 500);
        login.create(transaction).await.expect("create setup login");
        let bind_preconditions: (
            String,
            Option<Uuid>,
            i64,
            String,
            Option<String>,
            String,
            String,
            i64,
            i64,
        ) = sqlx::query_as(
            r"
            SELECT installation.state, installation.setup_transaction_id,
                   installation.updated_at_ms, installation.expected_provider_id,
                   login.tenant_id, login.purpose, login.provider_id,
                   login.created_at_ms, login.expires_at_ms
            FROM human_auth_installation_state AS installation
            JOIN human_login_transactions AS login ON login.id=$1
            ",
        )
        .bind(Uuid::parse_str(LOGIN_ID)?)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(bind_preconditions.0, "pending");
        assert_eq!(bind_preconditions.1, None);
        assert!(bind_preconditions.2 > 0);
        assert_eq!(bind_preconditions.3, "github");
        assert_eq!(bind_preconditions.4, None);
        assert_eq!(bind_preconditions.5, "installation_setup");
        assert_eq!(bind_preconditions.6, "github");
        assert!(bind_preconditions.7 >= bind_preconditions.2);
        assert!(bind_preconditions.8 > bind_preconditions.7);
        let bound = installation
            .bind_login(BindInstallationLogin::new(
                revision,
                proof(0x71),
                LoginTransactionId::new(LOGIN_ID).expect("login"),
                scenario_time(120),
            ))
            .await
            .expect("bind setup login");
        let InstallationState::LoginBound { revision, .. } = bound else {
            panic!("setup login must be bound")
        };
        assert_eq!(revision, InstallationRevision::new(3).expect("revision"));
        assert!(matches!(
            login
                .consume(ConsumeLoginTransaction::new(access, scenario_time(130),))
                .await
                .expect("consume setup login"),
            ConsumeLoginTransactionOutcome::Consumed(_)
        ));

        sqlx::query(
            r"
            INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
            VALUES ('bootstrap-tenant', 'bootstrap-tenant', 1, 1)
            ",
        )
        .execute(database.pool())
        .await?;

        let completion_seconds = clock
            .now()
            .await?
            .checked_add(999)
            .expect("completion time")
            / 1_000;
        let completion_now_ms = completion_seconds
            .checked_mul(1_000)
            .expect("completion time in milliseconds");
        clock.set(completion_now_ms).await?;
        let completed_at = UnixTimestamp::from_seconds(u64::try_from(completion_seconds)?);
        let first = Arc::clone(&installation);
        let second = Arc::clone(&installation);
        let first_request =
            completion_for_at(database.pool(), LOGIN_ID, ACCESS_A, REFRESH_A, completed_at);
        let second_request =
            completion_for_at(database.pool(), LOGIN_ID, ACCESS_B, REFRESH_B, completed_at);
        let (first_outcome, second_outcome) = tokio::join!(
            first.complete(first_request),
            second.complete(second_request),
        );
        let outcomes = [first_outcome, second_outcome];
        assert_eq!(
            outcomes.iter().filter(|result| result.is_ok()).count(),
            1,
            "completion outcomes: {outcomes:?}"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(InstallationRepositoryError::VersionConflict
                        | InstallationRepositoryError::AlreadyConfigured)
                ))
                .count(),
            1
        );
        let completed = outcomes
            .iter()
            .find_map(|result| match result {
                Ok(CompleteInstallationOutcome::Completed(completed)) => Some(completed),
                Ok(CompleteInstallationOutcome::SessionConflict { .. }) | Err(_) => None,
            })
            .expect("one completion");
        assert_eq!(completed.authorization_revision(), 3);
        assert_eq!(
            completed.revision(),
            InstallationRevision::new(4).expect("revision")
        );
        assert_eq!(
            completed.session().identity().tenant_id(),
            completed.tenant_id()
        );
        assert_eq!(
            completed.session().identity().principal_id(),
            completed.principal_id()
        );

        let InstallationState::Configured {
            principal_id,
            revision,
            ..
        } = installation
            .load()
            .await
            .expect("load configured installation")
        else {
            panic!("installation must be configured")
        };
        assert_eq!(principal_id, completed.principal_id().clone());
        assert_eq!(revision, completed.revision());
        let tenant_display_name: String =
            sqlx::query_scalar("SELECT display_name FROM tenants WHERE id='bootstrap-tenant'")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(tenant_display_name, "Bootstrap Tenant");

        let provider_key = ProviderTokenKey::new(
            TenantId::new("bootstrap-tenant").expect("tenant"),
            ProviderId::new("github").expect("provider"),
            ProviderSubject::new("424242").expect("subject"),
        );
        let vault = PostgresProviderTokenVault::new(database.pool().clone(), keyring);
        let stored_tokens = vault
            .load(&provider_key)
            .await
            .expect("load encrypted provider tokens");
        assert_eq!(stored_tokens.version().value(), 1);
        let winning_access = stored_tokens.tokens().access_token().expose_secret();
        assert!(winning_access == ACCESS_A || winning_access == ACCESS_B);

        let atomic_authority: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT snapshot.provider_token_version, token.version,
                   membership.authorization_revision, session.authorization_revision,
                   (SELECT count(*)
                    FROM github_organization_membership_observations AS organization
                    WHERE organization.tenant_id=snapshot.tenant_id
                      AND organization.snapshot_id=snapshot.id)
            FROM github_membership_snapshots AS snapshot
            JOIN human_provider_tokens AS token
              ON token.tenant_id=snapshot.tenant_id
             AND token.principal_id=snapshot.principal_id
             AND token.provider_id=snapshot.provider_id
             AND token.provider_subject=snapshot.provider_subject
             AND token.revoked_at_ms IS NULL
            JOIN tenant_human_memberships AS membership
              ON membership.tenant_id=snapshot.tenant_id
             AND membership.principal_id=snapshot.principal_id
            JOIN human_sessions AS session
              ON session.tenant_id=snapshot.tenant_id
             AND session.principal_id=snapshot.principal_id
             AND session.id=$3
            WHERE snapshot.tenant_id=$1 AND snapshot.id=$2
            ",
        )
        .bind(completed.tenant_id().as_str())
        .bind(Uuid::parse_str(LOGIN_ID)?)
        .bind(Uuid::parse_str(
            completed.session().identity().session_id().as_str(),
        )?)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(atomic_authority, (1, 1, 3, 3, 1));
        assert_eq!(
            completed.session().authorization_revision(),
            u64::try_from(atomic_authority.3)?
        );

        let token_envelope: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            r"
            SELECT encrypted_payload, payload_nonce, wrapped_data_key
            FROM human_provider_tokens
            WHERE tenant_id='bootstrap-tenant' AND revoked_at_ms IS NULL
            ",
        )
        .fetch_one(database.pool())
        .await?;
        for durable in [&token_envelope.0, &token_envelope.1, &token_envelope.2] {
            for sentinel in [ACCESS_A, ACCESS_B, REFRESH_A, REFRESH_B] {
                assert!(
                    !durable
                        .windows(sentinel.len())
                        .any(|window| window == sentinel.as_bytes())
                );
            }
        }

        let bootstrap_counts: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM human_principals),
              (SELECT count(*) FROM human_provider_identities),
              (SELECT count(*) FROM tenant_human_memberships),
              (SELECT count(*) FROM rbac_roles WHERE role_kind='built_in' AND immutable),
              (SELECT count(*) FROM rbac_role_bindings
                 WHERE assignment_source='bootstrap' AND scope_kind='tenant' AND status='active'),
              (SELECT count(*) FROM security_audit_events
                 WHERE action='auth.installation.configured' AND actor_kind='system')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(bootstrap_counts, (1, 1, 1, 1, 1, 1));
        let permission_counts: (i64, i64) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM rbac_permissions),
              (SELECT count(*) FROM rbac_role_permissions)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert!(permission_counts.0 > 0);
        assert_eq!(permission_counts.0, permission_counts.1);
        let durable_state: (String, Option<Vec<u8>>, Option<String>, String, i64, String) =
            sqlx::query_as(
                r"
            SELECT installation.state, installation.bootstrap_token_hash,
                   installation.bootstrap_hash_key_id, login.status,
                   membership.authorization_revision, identity.normalized_login
            FROM human_auth_installation_state AS installation
            JOIN human_login_transactions AS login
              ON login.id=installation.setup_transaction_id
            JOIN tenant_human_memberships AS membership
              ON membership.tenant_id=installation.configured_tenant_id
             AND membership.principal_id=installation.configured_principal_id
            JOIN human_provider_identities AS identity
              ON identity.principal_id=installation.configured_principal_id
            ",
            )
            .fetch_one(database.pool())
            .await?;
        assert_eq!(durable_state.0, "configured");
        assert_eq!(durable_state.1, None);
        assert_eq!(durable_state.2, None);
        assert_eq!(durable_state.3, "succeeded");
        assert_eq!(durable_state.4, 3);
        assert_eq!(durable_state.5, "octocat");

        let singleton_delete = sqlx::query("DELETE FROM human_auth_installation_state")
            .execute(database.pool())
            .await
            .expect_err("singleton deletion must fail");
        assert_eq!(
            singleton_delete
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("human_auth_installation_state_singleton_immutable")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn unavailable_token_encryption_rolls_back_every_bootstrap_write_and_is_retryable()
-> TestResult {
    run_with_database(|database| async move {
        let local_keyring = keyring();
        let installation =
            PostgresInstallationRepository::new(database.pool().clone(), local_keyring.clone());
        let login =
            PostgresLoginTransactionRepository::new(database.pool().clone(), local_keyring.clone());
        let armed = installation
            .arm(ArmInstallationSetup::new(
                tenant(),
                proof(0x41),
                ProviderId::new("github").expect("provider"),
                ProviderSubject::new("424242").expect("subject"),
                scenario_time(100),
                scenario_time(600),
            )?)
            .await?;
        let revision = armed.revision();
        let (transaction, access) = login_transaction(RETRY_LOGIN_ID, 0x51, 110, 500);
        login.create(transaction).await?;
        let bound = installation
            .bind_login(BindInstallationLogin::new(
                revision,
                proof(0x41),
                LoginTransactionId::new(RETRY_LOGIN_ID).expect("login"),
                scenario_time(120),
            ))
            .await?;
        assert_eq!(
            bound.revision(),
            InstallationRevision::new(3).expect("revision")
        );
        assert!(matches!(
            login
                .consume(ConsumeLoginTransaction::new(access, scenario_time(130),))
                .await?,
            ConsumeLoginTransactionOutcome::Consumed(_)
        ));

        let unavailable = PostgresInstallationRepository::new(
            database.pool().clone(),
            Arc::new(UnavailableKeyProvider),
        );
        assert_eq!(
            unavailable
                .complete(completion_for(
                    database.pool(),
                    RETRY_LOGIN_ID,
                    "unavailable-access-sentinel",
                    "unavailable-refresh-sentinel",
                ))
                .await
                .expect_err("unavailable wrapping provider must fail"),
            InstallationRepositoryError::Unavailable
        );
        let counts_after_failure: (i64, i64, i64, i64, i64, i64, String) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM human_principals),
              (SELECT count(*) FROM tenant_human_memberships),
              (SELECT count(*) FROM rbac_roles),
              (SELECT count(*) FROM human_provider_tokens),
              (SELECT count(*) FROM github_membership_snapshots),
              (SELECT count(*) FROM human_sessions),
              (SELECT status FROM human_login_transactions WHERE id=$1)
            ",
        )
        .bind(Uuid::parse_str(RETRY_LOGIN_ID)?)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            counts_after_failure,
            (0, 0, 0, 0, 0, 0, "consumed".to_owned())
        );
        assert!(matches!(
            installation.load().await?,
            InstallationState::LoginBound { revision, .. }
                if revision == InstallationRevision::new(3).expect("revision")
        ));

        let completed = installation
            .complete(completion_for(
                database.pool(),
                RETRY_LOGIN_ID,
                "retry-access-sentinel",
                "retry-refresh-sentinel",
            ))
            .await?;
        let CompleteInstallationOutcome::Completed(completed) = completed else {
            panic!("retry must atomically complete the installation")
        };
        assert_eq!(completed.authorization_revision(), 3);
        Ok(())
    })
    .await
}
