mod support;

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_auth::{
    github::{
        GithubMembershipObservation, GithubMembershipSnapshot, GithubMembershipSnapshotId,
        GithubOrganizationId, GithubOrganizationLogin, GithubOrganizationMembership,
        GithubOrganizationMembershipRole,
    },
    human::{ProviderId, ProviderIdentityAssertion, ProviderSubject, TenantId},
    login::{
        ConsumeLoginTransaction, ConsumeLoginTransactionOutcome, CreateLoginTransactionOutcome,
        LoginBindingDigest, LoginBindingDigestKeyId, LoginReturnPath, LoginTransaction,
        LoginTransactionAccess, LoginTransactionBinding, LoginTransactionFlow, LoginTransactionId,
        LoginTransactionPurpose, LoginTransactionRepository, LoginTransactionState,
        LoginTransactionVersion,
    },
    secret::{SecretBytes as AuthSecretBytes, SecretString, SystemSecureRandom},
    session::{
        ResolveSessionOutcome, SessionKind, SessionTokenDigest, SessionTokenDigestKeyId,
        SessionTokenLookup,
    },
    session_credential::{
        SessionCredential, SessionCredentialKey, SessionCredentialKeyring, SessionCredentialService,
    },
    sign_in::{
        FinalizeSignIn, FinalizeSignInOutcome, HumanSignInFinalizer, PendingSessionCandidate,
        PendingSessionConflict, SignInFinalizerError,
    },
    time::{Clock, UnixTimestamp},
    vault::{
        ProviderAccessToken, ProviderGrantKind, ProviderRefreshToken, ProviderTokenKey,
        ProviderTokenMetadata, ProviderTokenSet, ProviderTokenVault,
    },
};
use automata_ci_auth_postgres::{
    PostgresHumanSessionRepository, PostgresHumanSignInFinalizer,
    PostgresLoginTransactionRepository, PostgresProviderTokenVault,
};
use automata_ci_key_management::{
    KeyEncryptionContext, KeyEncryptionError, KeyEncryptionProvider, KeyId, LocalAes256GcmKeyring,
    LocalKeyMaterial, SecretBytes, WrappedDataKey,
};
use automata_ci_postgres_test_support::TestClock;
use sqlx::PgPool;
use uuid::Uuid;

use support::{TestResult, run_with_database};

const TENANT: &str = "tenant-a";
const SUBJECT: &str = "424242";
const SESSION_KEY_ID: &str = "sign-in-session-hmac-v1";
const ACCESS_SENTINEL: &str = "sign-in-access-token-sentinel";
const REFRESH_SENTINEL: &str = "sign-in-refresh-token-sentinel";
const SCENARIO_REFERENCE_SECONDS: u64 = 180;
const SCENARIO_REFERENCE_MILLISECONDS: i64 = 180_000;

fn now() -> UnixTimestamp {
    UnixTimestamp::from_seconds(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_secs(),
    )
}

fn scenario_time(seconds: u64) -> UnixTimestamp {
    let current = now().as_seconds();
    let rebased = if seconds >= SCENARIO_REFERENCE_SECONDS {
        current.checked_add(seconds - SCENARIO_REFERENCE_SECONDS)
    } else {
        current.checked_sub(SCENARIO_REFERENCE_SECONDS - seconds)
    }
    .expect("scenario time");
    UnixTimestamp::from_seconds(rebased)
}

fn scenario_milliseconds(milliseconds: i64) -> i64 {
    let current = i64::try_from(now().as_seconds())
        .expect("test time fits i64")
        .checked_mul(1000)
        .expect("test milliseconds");
    current
        .checked_add(milliseconds - SCENARIO_REFERENCE_MILLISECONDS)
        .expect("scenario timestamp")
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
        KeyId::new("sign-in-kek-v1").expect("key ID"),
        SecretBytes::new(vec![0x73; 32]).expect("key material"),
    )
    .expect("local key material");
    Arc::new(LocalAes256GcmKeyring::new(material, Vec::new(), []).expect("local keyring"))
}

fn provider(value: &str) -> ProviderId {
    ProviderId::new(value).expect("provider ID")
}

fn subject(value: &str) -> ProviderSubject {
    ProviderSubject::new(value).expect("provider subject")
}

fn binding(key: &str, byte: u8) -> LoginTransactionBinding {
    LoginTransactionBinding::new(
        LoginBindingDigestKeyId::new(key).expect("binding key ID"),
        LoginBindingDigest::new([byte; 32]),
    )
}

fn browser_access(
    id: &str,
    tenant: &str,
    provider_id: &str,
    state_byte: u8,
) -> LoginTransactionAccess {
    LoginTransactionAccess::browser(
        LoginTransactionId::new(id).expect("login ID"),
        LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new(tenant).expect("tenant ID"),
        },
        provider(provider_id),
        binding("oauth-state-v1", state_byte),
        binding("browser-client-v1", state_byte.wrapping_add(1)),
    )
    .expect("independent browser proofs")
}

fn browser_transaction(
    id: &str,
    tenant: &str,
    state_byte: u8,
    expires_at: u64,
) -> LoginTransaction {
    let created_at = now();
    LoginTransaction::new(
        LoginTransactionId::new(id).expect("login ID"),
        LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new(tenant).expect("tenant ID"),
        },
        provider("github"),
        LoginTransactionFlow::browser(
            binding("oauth-state-v1", state_byte),
            binding("browser-client-v1", state_byte.wrapping_add(1)),
        )
        .expect("browser flow"),
        Some(LoginReturnPath::new("/workflows").expect("return path")),
        LoginTransactionState::new(
            AuthSecretBytes::new(b"pkce-verifier-login-sentinel".to_vec()).expect("login state"),
        ),
        created_at,
        created_at
            .checked_add(expires_at.checked_sub(100).expect("test lifetime"))
            .expect("login expiry"),
    )
    .expect("login transaction")
}

fn device_access(id: &str, poll_byte: u8) -> LoginTransactionAccess {
    LoginTransactionAccess::device(
        LoginTransactionId::new(id).expect("login ID"),
        LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new(TENANT).expect("tenant ID"),
        },
        provider("github"),
        binding("device-poll-v1", poll_byte),
    )
}

fn device_transaction(id: &str, poll_byte: u8, expires_at: u64) -> LoginTransaction {
    let created_at = now();
    LoginTransaction::new(
        LoginTransactionId::new(id).expect("login ID"),
        LoginTransactionPurpose::SignIn {
            tenant_id: TenantId::new(TENANT).expect("tenant ID"),
        },
        provider("github"),
        LoginTransactionFlow::device(
            binding("device-poll-v1", poll_byte),
            SecretString::new("ABCD-EFGH").expect("user code"),
            "https://github.com/login/device",
            5_000,
            created_at.checked_add(10).expect("next poll"),
        )
        .expect("device flow"),
        None,
        LoginTransactionState::new(
            AuthSecretBytes::new(b"device-code-sentinel".to_vec()).expect("device state"),
        ),
        created_at,
        created_at
            .checked_add(expires_at.checked_sub(100).expect("test lifetime"))
            .expect("login expiry"),
    )
    .expect("device transaction")
}

async fn create_consumed_login(
    pool: &PgPool,
    encryption: Arc<LocalAes256GcmKeyring>,
    id: &str,
    state_byte: u8,
    expires_at: u64,
) -> TestResult<LoginTransactionAccess> {
    let repository = PostgresLoginTransactionRepository::new(pool.clone(), encryption);
    assert_eq!(
        repository
            .create(browser_transaction(id, TENANT, state_byte, expires_at))
            .await?,
        CreateLoginTransactionOutcome::Created(
            LoginTransactionVersion::new(1).expect("initial version")
        )
    );
    let access = browser_access(id, TENANT, "github", state_byte);
    assert!(matches!(
        repository
            .consume(
                ConsumeLoginTransaction::new(access.clone(), now())
                    .if_version(LoginTransactionVersion::new(1).expect("pending version")),
            )
            .await?,
        ConsumeLoginTransactionOutcome::Consumed(_)
    ));
    Ok(access)
}

async fn create_consumed_device_login(
    pool: &PgPool,
    encryption: Arc<LocalAes256GcmKeyring>,
    id: &str,
    poll_byte: u8,
    expires_at: u64,
) -> TestResult<LoginTransactionAccess> {
    let repository = PostgresLoginTransactionRepository::new(pool.clone(), encryption);
    assert_eq!(
        repository
            .create(device_transaction(id, poll_byte, expires_at))
            .await?,
        CreateLoginTransactionOutcome::Created(
            LoginTransactionVersion::new(1).expect("initial version")
        )
    );
    let access = device_access(id, poll_byte);
    assert!(matches!(
        repository
            .consume(
                ConsumeLoginTransaction::new(access.clone(), now())
                    .if_version(LoginTransactionVersion::new(1).expect("pending version")),
            )
            .await?,
        ConsumeLoginTransactionOutcome::Consumed(_)
    ));
    Ok(access)
}

async fn seed_tenant(pool: &PgPool) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ($1,'Tenant A',100000,100000)",
    )
    .bind(TENANT)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_human(
    pool: &PgPool,
    provider_subject: &str,
    first_authenticated_at_ms: i64,
    authorization_revision: i64,
) -> TestResult<Uuid> {
    let first_authenticated_at_ms = scenario_milliseconds(first_authenticated_at_ms);
    let principal_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO human_principals (
            id,status,display_name,created_at_ms,updated_at_ms
        ) VALUES ($1,'active','Durable Principal',100000,100000)
        ",
    )
    .bind(principal_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id,provider_id,provider_subject,provider_login,
            normalized_login,display_name,first_authenticated_at_ms,
            last_authenticated_at_ms,last_observed_at_ms,created_at_ms,updated_at_ms
        ) VALUES ($1,'github',$2,'old-login','old-login','Old Display',$3,$3,$3,100000,$3)
        ",
    )
    .bind(principal_id)
    .bind(provider_subject)
    .bind(first_authenticated_at_ms)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id,principal_id,status,authorization_revision,
            created_at_ms,updated_at_ms
        ) VALUES ($1,$2,'active',$3,100000,100000)
        ",
    )
    .bind(TENANT)
    .bind(principal_id)
    .bind(authorization_revision)
    .execute(pool)
    .await?;
    Ok(principal_id)
}

fn identity(
    provider_id: &str,
    provider_subject: &str,
    login: &str,
    at: u64,
) -> ProviderIdentityAssertion {
    ProviderIdentityAssertion::new(
        provider(provider_id),
        subject(provider_subject),
        login,
        Some("New Display".to_owned()),
        scenario_time(at),
    )
    .expect("provider identity")
}

fn provider_tokens(
    provider_id: &str,
    provider_subject: &str,
    access_token: &str,
    refresh_token: &str,
    issued_at: u64,
) -> ProviderTokenSet {
    let metadata = ProviderTokenMetadata::builder(
        provider(provider_id),
        ProviderGrantKind::BrowserAuthorizationCode,
        "Bearer",
        scenario_time(issued_at),
    )
    .provider_subject(Some(subject(provider_subject)))
    .scopes(BTreeSet::from(["read:org".to_owned(), "repo".to_owned()]))
    .access_expires_at(Some(scenario_time(1_000)))
    .refresh_expires_at(Some(scenario_time(2_000)))
    .build()
    .expect("provider token metadata");
    ProviderTokenSet::new(
        ProviderAccessToken::new(SecretString::new(access_token).expect("access token")),
        Some(ProviderRefreshToken::new(
            SecretString::new(refresh_token).expect("refresh token"),
        )),
        metadata,
    )
    .expect("provider token set")
}

fn device_provider_tokens(
    provider_subject: &str,
    access_token: &str,
    refresh_token: &str,
    issued_at: u64,
) -> ProviderTokenSet {
    let metadata = ProviderTokenMetadata::builder(
        provider("github"),
        ProviderGrantKind::DeviceAuthorization,
        "Bearer",
        scenario_time(issued_at),
    )
    .provider_subject(Some(subject(provider_subject)))
    .scopes(BTreeSet::from(["read:org".to_owned(), "repo".to_owned()]))
    .access_expires_at(Some(scenario_time(1_000)))
    .refresh_expires_at(Some(scenario_time(2_000)))
    .build()
    .expect("device token metadata");
    ProviderTokenSet::new(
        ProviderAccessToken::new(SecretString::new(access_token).expect("access token")),
        Some(ProviderRefreshToken::new(
            SecretString::new(refresh_token).expect("refresh token"),
        )),
        metadata,
    )
    .expect("device provider token set")
}

struct PreparedFinalization {
    service: SessionCredentialService,
    credential: SessionCredential,
    session_id: String,
    request: FinalizeSignIn,
}

fn prepare_session(
    pool: &PgPool,
    kind: SessionKind,
    issued_at: u64,
) -> TestResult<(
    SessionCredentialService,
    SessionCredential,
    PendingSessionCandidate,
)> {
    prepare_session_at(pool, kind, scenario_time(issued_at))
}

fn prepare_session_at(
    pool: &PgPool,
    kind: SessionKind,
    issued_at: UnixTimestamp,
) -> TestResult<(
    SessionCredentialService,
    SessionCredential,
    PendingSessionCandidate,
)> {
    let hmac_key = SessionCredentialKey::new(
        automata_ci_auth::session::SessionTokenDigestKeyId::new(SESSION_KEY_ID)?,
        AuthSecretBytes::new(vec![0x5a; 32])?,
    )?;
    let service = SessionCredentialService::new(
        SessionCredentialKeyring::new(hmac_key, Vec::new())?,
        Arc::new(PostgresHumanSessionRepository::new(pool.clone())),
        Arc::new(SystemSecureRandom),
        Arc::new(FixedClock(issued_at)),
    );
    let prepared = service.prepare(kind, Duration::from_mins(2), Duration::from_mins(10))?;
    let (credential, candidate) = prepared.into_parts();
    Ok((service, credential, candidate))
}

#[allow(clippy::too_many_arguments)]
fn prepare_finalization(
    pool: &PgPool,
    access: LoginTransactionAccess,
    expected_version: u64,
    provider_id: &str,
    provider_subject: &str,
    login: &str,
    access_token: &str,
    refresh_token: &str,
    issued_at: u64,
    authenticated_at: u64,
    session_issued_at: u64,
    now: u64,
) -> TestResult<PreparedFinalization> {
    prepare_finalization_with_memberships(
        pool,
        access,
        expected_version,
        provider_id,
        provider_subject,
        login,
        access_token,
        refresh_token,
        issued_at,
        authenticated_at,
        session_issued_at,
        now,
        GithubMembershipSnapshot::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_finalization_with_memberships(
    pool: &PgPool,
    access: LoginTransactionAccess,
    expected_version: u64,
    provider_id: &str,
    provider_subject: &str,
    login: &str,
    access_token: &str,
    refresh_token: &str,
    issued_at: u64,
    authenticated_at: u64,
    session_issued_at: u64,
    now: u64,
    memberships: GithubMembershipSnapshot,
) -> TestResult<PreparedFinalization> {
    let (service, credential, candidate) =
        prepare_session(pool, SessionKind::Browser, session_issued_at)?;
    let session_id = candidate.session_id().as_str().to_owned();
    let membership = GithubMembershipObservation::new(
        GithubMembershipSnapshotId::new(access.id().as_str()).expect("snapshot ID"),
        memberships,
        scenario_time(authenticated_at),
        scenario_time(now.checked_add(700).expect("observation expiry")),
    )
    .expect("membership observation");
    let request = FinalizeSignIn::new(
        access,
        LoginTransactionVersion::new(expected_version)?,
        identity(provider_id, provider_subject, login, authenticated_at),
        provider_tokens(
            provider_id,
            provider_subject,
            access_token,
            refresh_token,
            issued_at,
        ),
        membership,
        candidate,
        scenario_time(now),
    )?;
    Ok(PreparedFinalization {
        service,
        credential,
        session_id,
        request,
    })
}

fn token_key(provider_subject: &str) -> ProviderTokenKey {
    ProviderTokenKey::new(
        TenantId::new(TENANT).expect("tenant"),
        provider("github"),
        subject(provider_subject),
    )
}

#[allow(clippy::too_many_arguments)]
async fn finalize_for(
    pool: &PgPool,
    finalizer: &PostgresHumanSignInFinalizer,
    access: LoginTransactionAccess,
    expected_version: u64,
    provider_id: &str,
    provider_subject: &str,
    authenticated_at: u64,
    session_issued_at: u64,
    now: u64,
) -> TestResult<FinalizeSignInOutcome> {
    let prepared = prepare_finalization(
        pool,
        access,
        expected_version,
        provider_id,
        provider_subject,
        "observed-login",
        "outcome-access-token",
        "outcome-refresh-token",
        authenticated_at.saturating_sub(10),
        authenticated_at,
        session_issued_at,
        now,
    )?;
    Ok(finalizer.finalize(prepared.request).await?)
}

async fn row_counts(pool: &PgPool) -> TestResult<(i64, i64, i64)> {
    Ok((
        sqlx::query_scalar("SELECT count(*) FROM human_sessions")
            .fetch_one(pool)
            .await?,
        sqlx::query_scalar("SELECT count(*) FROM human_provider_tokens")
            .fetch_one(pool)
            .await?,
        sqlx::query_scalar("SELECT count(*) FROM security_audit_events")
            .fetch_one(pool)
            .await?,
    ))
}

async fn seed_session(
    pool: &PgPool,
    principal_id: Uuid,
    session_id: Uuid,
    lookup: &SessionTokenLookup,
    authorization_revision: i64,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id,tenant_id,principal_id,provider_id,provider_subject,
            session_kind,audience,token_hash,token_hash_key_id,
            authorization_revision,issued_at_ms,last_seen_at_ms,
            idle_expires_at_ms,expires_at_ms
        ) VALUES ($1,$2,$3,'github',$4,'browser','automata.web',$5,$6,$7,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 10000,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 - 10000,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 110000,
                  floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000 + 590000)
        ",
    )
    .bind(session_id)
    .bind(TENANT)
    .bind(principal_id)
    .bind(SUBJECT)
    .bind(lookup.digest().as_bytes().as_slice())
    .bind(lookup.key_id().as_str())
    .bind(authorization_revision)
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn database_now_minus_sixty_cannot_commit_expired_provider_or_membership_authority()
-> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool).await?;
        let principal_id = seed_human(pool, SUBJECT, 100_000, 17).await?;
        let encryption = keyring();
        let login_id = "10101010-1010-4010-8010-101010101010";
        let access = create_consumed_login(pool, encryption.clone(), login_id, 0x10, 900).await?;
        let database_now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
                .fetch_one(pool)
                .await?;
        let database_now = u64::try_from(database_now)?;
        let caller_now =
            UnixTimestamp::from_seconds(database_now.checked_sub(60).expect("caller timestamp"));
        let provider_expiry =
            UnixTimestamp::from_seconds(database_now.checked_sub(1).expect("provider expiry"));
        let issued_at = UnixTimestamp::from_seconds(
            caller_now.as_seconds().checked_sub(20).expect("issue time"),
        );
        let authenticated_at = UnixTimestamp::from_seconds(
            caller_now
                .as_seconds()
                .checked_sub(10)
                .expect("authentication time"),
        );
        let observed_at = UnixTimestamp::from_seconds(
            caller_now
                .as_seconds()
                .checked_sub(5)
                .expect("observation time"),
        );
        let metadata = ProviderTokenMetadata::builder(
            provider("github"),
            ProviderGrantKind::BrowserAuthorizationCode,
            "Bearer",
            issued_at,
        )
        .provider_subject(Some(subject(SUBJECT)))
        .scopes(BTreeSet::from(["read:org".to_owned(), "repo".to_owned()]))
        .access_expires_at(Some(provider_expiry))
        .refresh_expires_at(Some(UnixTimestamp::from_seconds(
            database_now.checked_add(600).expect("refresh expiry"),
        )))
        .build()?;
        let tokens = ProviderTokenSet::new(
            ProviderAccessToken::new(SecretString::new("negative-skew-access")?),
            Some(ProviderRefreshToken::new(SecretString::new(
                "negative-skew-refresh",
            )?)),
            metadata,
        )?;
        let membership = GithubMembershipObservation::new(
            GithubMembershipSnapshotId::new(login_id)?,
            GithubMembershipSnapshot::default(),
            observed_at,
            provider_expiry,
        )?;
        let (_, _, candidate) = prepare_session_at(pool, SessionKind::Browser, caller_now)?;
        let request = FinalizeSignIn::new(
            access,
            LoginTransactionVersion::new(2)?,
            ProviderIdentityAssertion::new(
                provider("github"),
                subject(SUBJECT),
                "negative-skew-login",
                None,
                authenticated_at,
            )?,
            tokens,
            membership,
            candidate,
            caller_now,
        )?;
        let finalizer = PostgresHumanSignInFinalizer::new(pool.clone(), encryption);
        assert!(matches!(
            finalizer.finalize(request).await?,
            FinalizeSignInOutcome::Expired
        ));
        assert_eq!(row_counts(pool).await?, (0, 0, 0));
        let rolled_back: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM github_membership_snapshots),
              (SELECT count(*) FROM human_provider_identities WHERE revision<>1),
              (SELECT count(*) FROM human_sessions WHERE principal_id=$1)
            ",
        )
        .bind(principal_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(rolled_back, (0, 0, 0));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn consumed_sign_in_admits_stable_subject_rotates_tokens_and_commits_exact_session()
-> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool).await?;
        let principal_id = seed_human(pool, SUBJECT, 100_000, 17).await?;
        let encryption = keyring();
        let access = create_consumed_login(
            pool,
            encryption.clone(),
            "11111111-1111-4111-8111-111111111111",
            0x11,
            900,
        )
        .await?;
        let vault = PostgresProviderTokenVault::new(pool.clone(), encryption.clone());
        assert_eq!(
            vault
                .insert_if_absent(
                    &token_key(SUBJECT),
                    provider_tokens(
                        "github",
                        SUBJECT,
                        "old-access-token",
                        "old-refresh-token",
                        120,
                    ),
                )
                .await?
                .value(),
            1
        );

        let prepared = prepare_finalization(
            pool,
            access.clone(),
            2,
            "github",
            SUBJECT,
            "Renamed-Login",
            ACCESS_SENTINEL,
            REFRESH_SENTINEL,
            140,
            160,
            170,
            180,
        )?;
        let raw = prepared.credential.expose_secret().to_owned();
        let expected_session_id = prepared.session_id.clone();
        let request_debug = format!("{:?}", prepared.request);
        assert!(!request_debug.contains(&raw));
        assert!(!request_debug.contains(ACCESS_SENTINEL));
        assert!(!request_debug.contains(REFRESH_SENTINEL));

        let finalizer = PostgresHumanSignInFinalizer::new(pool.clone(), encryption.clone());
        let outcome = finalizer.finalize(prepared.request).await?;
        let FinalizeSignInOutcome::Admitted {
            human,
            session,
            current_authorization_revision,
            return_path,
        } = outcome
        else {
            panic!("stable provider subject should be admitted")
        };
        assert_eq!(human.principal_id().as_str(), principal_id.hyphenated().to_string());
        assert_eq!(human.provider_subject().as_str(), SUBJECT);
        assert_eq!(human.login(), "Renamed-Login");
        assert_eq!(session.identity().session_id().as_str(), expected_session_id);
        assert_eq!(session.identity().kind(), SessionKind::Browser);
        assert_eq!(session.identity().audience(), "automata.web");
        assert_eq!(session.authorization_revision(), 17);
        assert_eq!(current_authorization_revision, 17);
        assert_eq!(
            return_path.as_ref().map(LoginReturnPath::as_str),
            Some("/workflows")
        );

        let lookup = prepared
            .service
            .derive_lookup_raw(&raw, SessionKind::Browser)?;
        let session_row: (Uuid, Vec<u8>, String, String, i64) = sqlx::query_as(
            r"
            SELECT id,token_hash,token_hash_key_id,session_kind,authorization_revision
            FROM human_sessions
            ",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(session_row.0.hyphenated().to_string(), expected_session_id);
        assert_eq!(session_row.1, lookup.digest().as_bytes());
        assert_eq!(session_row.2, lookup.key_id().as_str());
        assert_eq!(session_row.3, "browser");
        assert_eq!(session_row.4, 17);

        let login_row: (String, i64, Option<Uuid>) = sqlx::query_as(
            "SELECT status,revision,completed_principal_id FROM human_login_transactions WHERE id=$1",
        )
        .bind(Uuid::parse_str("11111111-1111-4111-8111-111111111111")?)
        .fetch_one(pool)
        .await?;
        assert_eq!(login_row, ("succeeded".to_owned(), 3, Some(principal_id)));
        let identity_row: (String, String, Option<String>, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT provider_login,normalized_login,display_name,revision,
                   last_authenticated_at_ms,last_observed_at_ms
            FROM human_provider_identities
            WHERE provider_id='github' AND provider_subject=$1
            ",
        )
        .bind(SUBJECT)
        .fetch_one(pool)
        .await?;
        assert_eq!(identity_row.0, "Renamed-Login");
        assert_eq!(identity_row.1, "renamed-login");
        assert_eq!(identity_row.2.as_deref(), Some("New Display"));
        assert_eq!(identity_row.3, 2);
        assert!(identity_row.4 <= identity_row.5);
        let database_now_ms: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000",
        )
        .fetch_one(pool)
        .await?;
        assert!(identity_row.5.abs_diff(database_now_ms) <= 1_000);

        let stored_tokens = vault.load(&token_key(SUBJECT)).await?;
        assert_eq!(stored_tokens.version().value(), 2);
        assert_eq!(
            stored_tokens.tokens().access_token().expose_secret(),
            ACCESS_SENTINEL
        );
        assert_eq!(
            stored_tokens
                .tokens()
                .refresh_token()
                .expect("refresh token")
                .expose_secret(),
            REFRESH_SENTINEL
        );
        let encrypted_payload: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_payload FROM human_provider_tokens WHERE revoked_at_ms IS NULL",
        )
        .fetch_one(pool)
        .await?;
        assert!(!encrypted_payload
            .windows(ACCESS_SENTINEL.len())
            .any(|window| window == ACCESS_SENTINEL.as_bytes()));
        assert!(!encrypted_payload
            .windows(REFRESH_SENTINEL.len())
            .any(|window| window == REFRESH_SENTINEL.as_bytes()));

        let audit: (String, String, String, Option<Uuid>, Option<Uuid>, Option<i64>) =
            sqlx::query_as(
                r"
                SELECT action,outcome,actor_kind,actor_principal_id,
                       actor_session_id,authorization_revision
                FROM security_audit_events
                ",
            )
            .fetch_one(pool)
            .await?;
        assert_eq!(audit.0, "auth.sign_in");
        assert_eq!(audit.1, "succeeded");
        assert_eq!(audit.2, "human");
        assert_eq!(audit.3, Some(principal_id));
        assert_eq!(audit.4, Some(session_row.0));
        assert_eq!(audit.5, Some(17));
        assert_eq!(row_counts(pool).await?, (1, 1, 1));

        let replay = prepare_finalization(
            pool,
            access,
            2,
            "github",
            SUBJECT,
            "Renamed-Again",
            "replay-access-token",
            "replay-refresh-token",
            161,
            171,
            181,
            182,
        )?;
        assert!(matches!(
            finalizer.finalize(replay.request).await?,
            FinalizeSignInOutcome::AlreadyConsumed
        ));
        assert_eq!(row_counts(pool).await?, (1, 1, 1));
        assert_eq!(vault.load(&token_key(SUBJECT)).await?.version().value(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn authority_refresh_revision_is_persisted_before_the_same_transaction_session() -> TestResult
{
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool).await?;
        seed_human(pool, SUBJECT, 100_000, 17).await?;
        let encryption = keyring();
        let login_id = "12121212-1212-4212-8212-121212121212";
        let access = create_consumed_login(pool, encryption.clone(), login_id, 0x12, 900).await?;
        let organization_id = GithubOrganizationId::new(101).expect("organization ID");
        let memberships = GithubMembershipSnapshot::new(
            [GithubOrganizationMembership::new(
                organization_id,
                GithubOrganizationLogin::new("automata-ci").expect("organization login"),
                GithubOrganizationMembershipRole::Member,
            )],
            [],
        )
        .expect("membership snapshot");
        let prepared = prepare_finalization_with_memberships(
            pool,
            access,
            2,
            "github",
            SUBJECT,
            "member-login",
            "membership-access-token",
            "membership-refresh-token",
            140,
            160,
            170,
            180,
            memberships,
        )?;
        let expected_session_id = Uuid::parse_str(&prepared.session_id)?;
        let finalizer = PostgresHumanSignInFinalizer::new(pool.clone(), encryption);
        let FinalizeSignInOutcome::Admitted {
            session,
            current_authorization_revision,
            ..
        } = finalizer.finalize(prepared.request).await?
        else {
            panic!("fresh numeric membership authority must admit")
        };
        assert_eq!(current_authorization_revision, 18);
        assert_eq!(session.authorization_revision(), 18);

        let durable: (i64, i64, i64, Uuid, i64) = sqlx::query_as(
            r"
            SELECT membership.authorization_revision,
                   stored_session.authorization_revision,
                   snapshot.provider_token_version,
                   snapshot.id,
                   snapshot.observed_at_ms
            FROM tenant_human_memberships AS membership
            JOIN human_sessions AS stored_session
              ON stored_session.tenant_id=membership.tenant_id
             AND stored_session.principal_id=membership.principal_id
             AND stored_session.id=$1
            JOIN github_membership_snapshots AS snapshot
              ON snapshot.tenant_id=membership.tenant_id
             AND snapshot.principal_id=membership.principal_id
            WHERE membership.tenant_id=$2
            ",
        )
        .bind(expected_session_id)
        .bind(TENANT)
        .fetch_one(pool)
        .await?;
        assert_eq!(durable.0, 18);
        assert_eq!(durable.1, 18);
        assert_eq!(durable.2, 1);
        assert_eq!(durable.3, Uuid::parse_str(login_id)?);
        assert!(durable.4 > 0);
        let database_now_ms: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT * 1000",
        )
        .fetch_one(pool)
        .await?;
        assert!(durable.4 <= database_now_ms);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn device_sign_in_commits_only_a_bounded_pending_cli_session() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool).await?;
        seed_human(pool, SUBJECT, 100_000, 17).await?;
        let encryption = keyring();
        let login_id = "13131313-1313-4313-8313-131313131313";
        let access =
            create_consumed_device_login(pool, encryption.clone(), login_id, 0x13, 900).await?;
        let (service, credential, candidate) = prepare_session(pool, SessionKind::Cli, 170)?;
        let session_id = Uuid::parse_str(candidate.session_id().as_str())?;
        let raw = credential.expose_secret().to_owned();
        let membership = GithubMembershipObservation::new(
            GithubMembershipSnapshotId::new(login_id)?,
            GithubMembershipSnapshot::default(),
            scenario_time(160),
            scenario_time(900),
        )?;
        let request = FinalizeSignIn::new(
            access,
            LoginTransactionVersion::new(2)?,
            identity("github", SUBJECT, "device-login", 160),
            device_provider_tokens(SUBJECT, "device-access-token", "device-refresh-token", 140),
            membership,
            candidate,
            scenario_time(180),
        )?;
        let finalizer = PostgresHumanSignInFinalizer::new(pool.clone(), encryption);
        let FinalizeSignInOutcome::Admitted {
            session,
            current_authorization_revision,
            return_path,
            ..
        } = finalizer.finalize(request).await?
        else {
            panic!("current device identity must be admitted")
        };
        assert_eq!(session.identity().kind(), SessionKind::Cli);
        assert_eq!(session.identity().audience(), "automata.cli");
        assert_eq!(current_authorization_revision, 17);
        assert_eq!(return_path, None);

        let durable: (String, String, Option<i64>, Option<i64>, i64, i64) = sqlx::query_as(
            r"
            SELECT session_kind,lifecycle_status,activation_deadline_ms,
                   activated_at_ms,revision,issued_at_ms
            FROM human_sessions
            WHERE id=$1
            ",
        )
        .bind(session_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(durable.0, "cli");
        assert_eq!(durable.1, "pending_activation");
        assert_eq!(durable.2, Some(durable.5 + 300_000));
        assert_eq!(durable.3, None);
        assert_eq!(durable.4, 1);
        let login: (String, Option<Uuid>) = sqlx::query_as(
            "SELECT status,completed_principal_id FROM human_login_transactions WHERE id=$1",
        )
        .bind(Uuid::parse_str(login_id)?)
        .fetch_one(pool)
        .await?;
        assert_eq!(login.0, "succeeded");
        assert!(login.1.is_some());
        assert_eq!(
            service.resolve_raw(&raw, SessionKind::Cli).await?,
            ResolveSessionOutcome::NotYetValid
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn concurrent_finalizers_commit_one_exact_bearer_session_token_version_and_audit()
-> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool).await?;
        seed_human(pool, SUBJECT, 100_000, 23).await?;
        let encryption = keyring();
        let access = create_consumed_login(
            pool,
            encryption.clone(),
            "22222222-2222-4222-8222-222222222222",
            0x21,
            900,
        )
        .await?;
        let first = prepare_finalization(
            pool,
            access.clone(),
            2,
            "github",
            SUBJECT,
            "race-login",
            "race-access-a",
            "race-refresh-a",
            140,
            160,
            170,
            180,
        )?;
        let second = prepare_finalization(
            pool,
            access,
            2,
            "github",
            SUBJECT,
            "race-login",
            "race-access-b",
            "race-refresh-b",
            140,
            160,
            170,
            180,
        )?;
        let first_session_id = first.session_id.clone();
        let second_session_id = second.session_id.clone();
        assert_ne!(first_session_id, second_session_id);
        let first_raw = first.credential.expose_secret().to_owned();
        let second_raw = second.credential.expose_secret().to_owned();
        let first_finalizer = PostgresHumanSignInFinalizer::new(pool.clone(), encryption.clone());
        let second_finalizer = first_finalizer.clone();
        let (first_outcome, second_outcome) = tokio::join!(
            first_finalizer.finalize(first.request),
            second_finalizer.finalize(second.request),
        );
        let outcomes = [first_outcome?, second_outcome?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, FinalizeSignInOutcome::Admitted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, FinalizeSignInOutcome::AlreadyConsumed))
                .count(),
            1
        );
        let admitted_session_id = outcomes
            .iter()
            .find_map(|outcome| match outcome {
                FinalizeSignInOutcome::Admitted { session, .. } => {
                    Some(session.identity().session_id().as_str())
                }
                _ => None,
            })
            .expect("one admitted session");
        let (winning_raw, winning_service) = if admitted_session_id == first_session_id {
            (&first_raw, &first.service)
        } else {
            assert_eq!(admitted_session_id, second_session_id);
            (&second_raw, &second.service)
        };
        let winning_lookup =
            winning_service.derive_lookup_raw(winning_raw, SessionKind::Browser)?;
        let stored_lookup: (String, Vec<u8>) =
            sqlx::query_as("SELECT token_hash_key_id,token_hash FROM human_sessions")
                .fetch_one(pool)
                .await?;
        assert_eq!(stored_lookup.0, winning_lookup.key_id().as_str());
        assert_eq!(stored_lookup.1, winning_lookup.digest().as_bytes());
        assert_eq!(row_counts(pool).await?, (1, 1, 1));
        let login: (String, i64) =
            sqlx::query_as("SELECT status,revision FROM human_login_transactions WHERE id=$1")
                .bind(Uuid::parse_str("22222222-2222-4222-8222-222222222222")?)
                .fetch_one(pool)
                .await?;
        assert_eq!(login, ("succeeded".to_owned(), 3));
        let vault = PostgresProviderTokenVault::new(pool.clone(), encryption);
        assert_eq!(vault.load(&token_key(SUBJECT)).await?.version().value(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn unavailable_kms_rolls_back_finalization_but_preserves_consumed_tombstone() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool).await?;
        seed_human(pool, SUBJECT, 100_000, 31).await?;
        let encryption = keyring();
        let access = create_consumed_login(
            pool,
            encryption.clone(),
            "33333333-3333-4333-8333-333333333333",
            0x31,
            900,
        )
        .await?;
        let vault = PostgresProviderTokenVault::new(pool.clone(), encryption);
        vault
            .insert_if_absent(
                &token_key(SUBJECT),
                provider_tokens(
                    "github",
                    SUBJECT,
                    "kms-old-access",
                    "kms-old-refresh",
                    120,
                ),
            )
            .await?;
        let prepared = prepare_finalization(
            pool,
            access,
            2,
            "github",
            SUBJECT,
            "kms-new-login",
            "kms-new-access",
            "kms-new-refresh",
            140,
            160,
            170,
            180,
        )?;
        let unavailable =
            PostgresHumanSignInFinalizer::new(pool.clone(), Arc::new(UnavailableKeyProvider));
        assert_eq!(
            unavailable.finalize(prepared.request).await.unwrap_err(),
            SignInFinalizerError::Unavailable
        );

        let login: (String, i64, Option<Uuid>) = sqlx::query_as(
            "SELECT status,revision,completed_principal_id FROM human_login_transactions WHERE id=$1",
        )
        .bind(Uuid::parse_str("33333333-3333-4333-8333-333333333333")?)
        .fetch_one(pool)
        .await?;
        assert_eq!(login, ("consumed".to_owned(), 2, None));
        let identity: (String, i64, i64) = sqlx::query_as(
            "SELECT provider_login,revision,last_authenticated_at_ms FROM human_provider_identities WHERE provider_id='github' AND provider_subject=$1",
        )
        .bind(SUBJECT)
        .fetch_one(pool)
        .await?;
        assert_eq!(identity.0, "old-login");
        assert_eq!(identity.1, 1);
        assert!(identity.2 > 0);
        assert_eq!(row_counts(pool).await?, (0, 1, 0));
        let stored = vault.load(&token_key(SUBJECT)).await?;
        assert_eq!(stored.version().value(), 1);
        assert_eq!(
            stored.tokens().access_token().expose_secret(),
            "kms-old-access"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn finalizer_distinguishes_exact_access_and_closed_admission_outcomes_without_writes()
-> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        seed_tenant(pool).await?;
        seed_human(pool, SUBJECT, 100_000, 5).await?;
        let disabled_principal = seed_human(pool, "disabled-subject", 100_000, 7).await?;
        let suspended_principal = seed_human(pool, "suspended-subject", 100_000, 9).await?;
        seed_human(pool, "future-subject", 200_000, 11).await?;
        sqlx::query(
            r"
            UPDATE human_principals
            SET status='disabled',disabled_at_ms=140000,
                disabled_reason='test disable',updated_at_ms=140000,revision=revision+1
            WHERE id=$1
            ",
        )
        .bind(disabled_principal)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended',suspended_at_ms=140000,
                suspended_reason='test suspend',updated_at_ms=140000,revision=revision+1
            WHERE tenant_id=$1 AND principal_id=$2
            ",
        )
        .bind(TENANT)
        .bind(suspended_principal)
        .execute(pool)
        .await?;
        let encryption = keyring();
        let finalizer = PostgresHumanSignInFinalizer::new(pool.clone(), encryption.clone());
        let exact = create_consumed_login(
            pool,
            encryption.clone(),
            "44444444-4444-4444-8444-444444444444",
            0x41,
            900,
        )
        .await?;

        assert!(matches!(
            finalize_for(
                pool,
                &finalizer,
                browser_access(
                    "44444444-4444-4444-8444-444444444444",
                    TENANT,
                    "github",
                    0x42,
                ),
                2,
                "github",
                SUBJECT,
                160,
                170,
                180,
            )
            .await?,
            FinalizeSignInOutcome::NotFound
        ));
        assert!(matches!(
            finalize_for(
                pool,
                &finalizer,
                browser_access(
                    "44444444-4444-4444-8444-444444444444",
                    "tenant-b",
                    "github",
                    0x41,
                ),
                2,
                "github",
                SUBJECT,
                160,
                170,
                180,
            )
            .await?,
            FinalizeSignInOutcome::NotFound
        ));
        assert!(matches!(
            finalize_for(
                pool,
                &finalizer,
                browser_access(
                    "44444444-4444-4444-8444-444444444444",
                    TENANT,
                    "gitlab",
                    0x41,
                ),
                2,
                "gitlab",
                SUBJECT,
                160,
                170,
                180,
            )
            .await?,
            FinalizeSignInOutcome::NotFound
        ));
        assert!(matches!(
            finalize_for(
                pool,
                &finalizer,
                exact.clone(),
                3,
                "github",
                SUBJECT,
                160,
                170,
                180,
            )
            .await?,
            FinalizeSignInOutcome::VersionConflict
        ));

        for (id, state, provider_subject, expected) in [
            (
                "55555555-5555-4555-8555-555555555555",
                0x51,
                "unknown-subject",
                "unmapped",
            ),
            (
                "66666666-6666-4666-8666-666666666666",
                0x61,
                "disabled-subject",
                "disabled",
            ),
            (
                "77777777-7777-4777-8777-777777777777",
                0x71,
                "suspended-subject",
                "suspended",
            ),
            (
                "88888888-8888-4888-8888-888888888888",
                0x81,
                "future-subject",
                "identity_conflict",
            ),
        ] {
            let access = create_consumed_login(pool, encryption.clone(), id, state, 900).await?;
            let outcome = finalize_for(
                pool,
                &finalizer,
                access,
                2,
                "github",
                provider_subject,
                160,
                170,
                180,
            )
            .await?;
            assert!(match expected {
                "unmapped" => matches!(outcome, FinalizeSignInOutcome::Unmapped),
                "disabled" => matches!(outcome, FinalizeSignInOutcome::PrincipalDisabled),
                "suspended" => matches!(outcome, FinalizeSignInOutcome::MembershipSuspended),
                "identity_conflict" => {
                    matches!(outcome, FinalizeSignInOutcome::IdentityConflict)
                }
                _ => false,
            });
        }

        let expired = create_consumed_login(
            pool,
            encryption.clone(),
            "99999999-9999-4999-8999-999999999999",
            0x91,
            101,
        )
        .await?;
        let expired_at_ms: i64 =
            sqlx::query_scalar("SELECT expires_at_ms FROM human_login_transactions WHERE id=$1")
                .bind(Uuid::parse_str("99999999-9999-4999-8999-999999999999")?)
                .fetch_one(pool)
                .await?;
        clock.set(expired_at_ms).await?;
        assert!(matches!(
            finalize_for(
                pool, &finalizer, expired, 2, "github", SUBJECT, 160, 170, 180,
            )
            .await?,
            FinalizeSignInOutcome::Expired
        ));

        let repository = PostgresLoginTransactionRepository::new(pool.clone(), encryption);
        repository
            .create(browser_transaction(
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                TENANT,
                0xa1,
                900,
            ))
            .await?;
        let pending = browser_access(
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            TENANT,
            "github",
            0xa1,
        );
        assert!(matches!(
            finalize_for(
                pool, &finalizer, pending, 1, "github", SUBJECT, 160, 170, 180,
            )
            .await?,
            FinalizeSignInOutcome::NotFound
        ));
        assert_eq!(row_counts(pool).await?, (0, 0, 0));
        let exact_state: (String, i64) =
            sqlx::query_as("SELECT status,revision FROM human_login_transactions WHERE id=$1")
                .bind(Uuid::parse_str("44444444-4444-4444-8444-444444444444")?)
                .fetch_one(pool)
                .await?;
        assert_eq!(exact_state, ("consumed".to_owned(), 2));
        let changed_identities: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM human_provider_identities WHERE revision <> 1",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(changed_identities, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn session_collisions_return_linear_safe_retry_without_committing_partial_writes()
-> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_tenant(pool).await?;
        let principal_id = seed_human(pool, SUBJECT, 100_000, 13).await?;
        let encryption = keyring();
        let finalizer = PostgresHumanSignInFinalizer::new(pool.clone(), encryption.clone());
        let id_conflict_access = create_consumed_login(
            pool,
            encryption.clone(),
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            0xb1,
            900,
        )
        .await?;
        let id_conflict = prepare_finalization(
            pool,
            id_conflict_access,
            2,
            "github",
            SUBJECT,
            "collision-login",
            "collision-access",
            "collision-refresh",
            140,
            160,
            170,
            180,
        )?;
        let unrelated_lookup = SessionTokenLookup::new(
            SessionTokenDigestKeyId::new("unrelated-session-hmac-v1")?,
            SessionTokenDigest::new([0x9a; 32]),
        );
        seed_session(
            pool,
            principal_id,
            Uuid::parse_str(&id_conflict.session_id)?,
            &unrelated_lookup,
            13,
        )
        .await?;
        let outcome = finalizer.finalize(id_conflict.request).await?;
        let FinalizeSignInOutcome::SessionConflict { conflict, retry } = outcome else {
            panic!("session ID collision must return a retry owner")
        };
        assert_eq!(conflict, PendingSessionConflict::SessionId);
        let retry_debug = format!("{retry:?}");
        assert!(retry_debug.contains("RetryFinalizeSignIn"));
        assert!(!retry_debug.contains("collision-access"));
        assert_eq!(row_counts(pool).await?, (1, 0, 0));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM github_membership_snapshots")
                .fetch_one(pool)
                .await?,
            0
        );
        let id_login: (String, i64) =
            sqlx::query_as("SELECT status,revision FROM human_login_transactions WHERE id=$1")
                .bind(Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")?)
                .fetch_one(pool)
                .await?;
        assert_eq!(id_login, ("consumed".to_owned(), 2));
        drop(id_conflict.credential);

        let (_retry_service, retry_credential, retry_candidate) =
            prepare_session(pool, SessionKind::Browser, 181)?;
        let retry_request = retry.with_session(retry_candidate, scenario_time(182))?;
        assert!(matches!(
            finalizer.finalize(retry_request).await?,
            FinalizeSignInOutcome::Admitted { .. }
        ));
        drop(retry_credential);
        assert_eq!(row_counts(pool).await?, (2, 1, 1));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM github_membership_snapshots")
                .fetch_one(pool)
                .await?,
            1
        );

        let digest_conflict_access = create_consumed_login(
            pool,
            encryption.clone(),
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            0xc1,
            900,
        )
        .await?;
        let digest_conflict = prepare_finalization(
            pool,
            digest_conflict_access,
            2,
            "github",
            SUBJECT,
            "collision-login-two",
            "collision-access-two",
            "collision-refresh-two",
            180,
            190,
            200,
            210,
        )?;
        let collided_lookup = digest_conflict.service.derive_lookup_raw(
            digest_conflict.credential.expose_secret(),
            SessionKind::Browser,
        )?;
        seed_session(pool, principal_id, Uuid::new_v4(), &collided_lookup, 13).await?;
        let outcome = finalizer.finalize(digest_conflict.request).await?;
        let FinalizeSignInOutcome::SessionConflict { conflict, retry } = outcome else {
            panic!("token digest collision must return a retry owner")
        };
        assert_eq!(conflict, PendingSessionConflict::TokenDigest);
        assert_eq!(retry.expected_version().value(), 2);
        assert_eq!(retry.identity().provider_subject().as_str(), SUBJECT);
        assert_eq!(row_counts(pool).await?, (3, 1, 1));
        let digest_login: (String, i64) =
            sqlx::query_as("SELECT status,revision FROM human_login_transactions WHERE id=$1")
                .bind(Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc")?)
                .fetch_one(pool)
                .await?;
        assert_eq!(digest_login, ("consumed".to_owned(), 2));
        let token_version: i64 = sqlx::query_scalar(
            "SELECT version FROM human_provider_tokens WHERE revoked_at_ms IS NULL",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(token_version, 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM github_membership_snapshots")
                .fetch_one(pool)
                .await?,
            1,
            "the collided second observation must roll back"
        );
        Ok(())
    })
    .await
}
