use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_auth::{
    human::ProviderId,
    login::{
        CreateLoginTransactionOutcome, LoadLoginTransactionOutcome, LoginBindingDigest,
        LoginBindingDigestKeyId, LoginTransaction, LoginTransactionAccess, LoginTransactionBinding,
        LoginTransactionFlow, LoginTransactionId, LoginTransactionPurpose,
        LoginTransactionRepository, LoginTransactionRepositoryError, LoginTransactionState,
        LoginTransactionVersion, ReplaceLoginTransactionOutcome, ReplaceLoginTransactionState,
    },
    secret::{SecretBytes as AuthSecretBytes, SecretString},
    time::UnixTimestamp,
};
use automata_ci_auth_postgres::PostgresLoginTransactionRepository;
use automata_ci_key_management::{KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes};
use automata_ci_postgres_test_support::TestClock;
use sqlx::PgPool;
use uuid::Uuid;

use super::support::{TestResult, run_with_database};

const LOGIN_ID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

fn now() -> UnixTimestamp {
    UnixTimestamp::from_seconds(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_secs(),
    )
}

fn scenario_time(seconds: u64) -> UnixTimestamp {
    now()
        .checked_add(seconds.saturating_sub(115))
        .expect("scenario time")
}

fn keyring() -> Arc<LocalAes256GcmKeyring> {
    let material = LocalKeyMaterial::new(
        KeyId::new("device-cas-kek-v1").expect("key ID"),
        SecretBytes::new(vec![0x61; 32]).expect("key bytes"),
    )
    .expect("key material");
    Arc::new(LocalAes256GcmKeyring::new(material, Vec::new(), []).expect("keyring"))
}

fn poll_binding() -> LoginTransactionBinding {
    LoginTransactionBinding::new(
        LoginBindingDigestKeyId::new("device-poll-v1").expect("binding key ID"),
        LoginBindingDigest::new([0x71; 32]),
    )
}

fn access() -> LoginTransactionAccess {
    LoginTransactionAccess::device(
        LoginTransactionId::new(LOGIN_ID).expect("login ID"),
        LoginTransactionPurpose::InstallationSetup,
        ProviderId::new("github").expect("provider ID"),
        poll_binding(),
    )
}

fn replacement(
    state: &'static [u8],
    next_poll_at: u64,
    poll_interval_milliseconds: u64,
) -> ReplaceLoginTransactionState {
    ReplaceLoginTransactionState::new(
        access(),
        LoginTransactionVersion::new(1).expect("version"),
        LoginTransactionState::new(AuthSecretBytes::new(state.to_vec()).expect("state")),
    )
    .next_device_poll_at(scenario_time(next_poll_at))
    .device_poll_interval_milliseconds(poll_interval_milliseconds)
}

async fn assert_invalid_intervals_leave_schedule_unchanged(
    repository: &PostgresLoginTransactionRepository,
    pool: &PgPool,
) -> TestResult {
    for (state, interval) in [
        (b"invalid-low".as_slice(), 999),
        (b"invalid-high".as_slice(), 300_001),
    ] {
        assert_eq!(
            repository
                .replace_state(replacement(state, 120, interval), now(),)
                .await
                .expect_err("out-of-bounds interval must fail before persistence"),
            LoginTransactionRepositoryError::InvalidRequest
        );
    }
    let unchanged: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT poll_interval_ms,next_poll_at_ms,revision,created_at_ms FROM human_login_transactions WHERE id=$1",
    )
    .bind(Uuid::parse_str(LOGIN_ID)?)
    .fetch_one(pool)
    .await?;
    assert_eq!(unchanged.0, 5_000);
    assert_eq!(unchanged.1 - unchanged.3, 10_000);
    assert_eq!(unchanged.2, 1);
    Ok(())
}

async fn race_replacements_and_assert_consistent_winner(
    repository: &Arc<PostgresLoginTransactionRepository>,
    pool: &PgPool,
) -> TestResult {
    let first_repository = Arc::clone(repository);
    let second_repository = Arc::clone(repository);
    let (first, second) = tokio::join!(
        first_repository.replace_state(replacement(b"winning-state-a", 125, 10_000), now(),),
        second_repository.replace_state(replacement(b"winning-state-b", 130, 15_000), now(),)
    );
    let outcomes = [first?, second?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ReplaceLoginTransactionOutcome::Replaced(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ReplaceLoginTransactionOutcome::VersionConflict))
            .count(),
        1
    );

    let LoadLoginTransactionOutcome::Active(loaded) = repository.load(&access(), now()).await?
    else {
        panic!("winning device transaction must remain active")
    };
    assert_eq!(
        loaded.version(),
        LoginTransactionVersion::new(2).expect("version")
    );
    let (_, _, _, interval, next_poll_at) = loaded
        .transaction()
        .flow()
        .device_parts()
        .expect("device metadata");
    let winning_state = loaded.transaction().state().expose_secret();
    assert!(
        (winning_state == b"winning-state-a" && interval == 10_000 && next_poll_at > now())
            || (winning_state == b"winning-state-b" && interval == 15_000 && next_poll_at > now())
    );

    let stored: (i64, i64, i64, Vec<u8>) = sqlx::query_as(
        "SELECT poll_interval_ms,next_poll_at_ms,revision,encrypted_payload FROM human_login_transactions WHERE id=$1",
    )
    .bind(Uuid::parse_str(LOGIN_ID)?)
    .fetch_one(pool)
    .await?;
    assert_eq!(stored.0, i64::try_from(interval)?);
    assert_eq!(stored.1, i64::try_from(next_poll_at.as_seconds())? * 1_000);
    assert_eq!(stored.2, 2);
    for plaintext in [
        b"initial-device-state".as_slice(),
        b"winning-state-a".as_slice(),
        b"winning-state-b".as_slice(),
    ] {
        assert!(
            !stored
                .3
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }
    Ok(())
}

async fn wait_for_blocked_transaction(pool: &PgPool) -> TestResult<bool> {
    for _ in 0..200 {
        let blocked: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM pg_stat_activity
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
async fn replacement_rebases_poll_delay_after_lock_wait_and_caller_skew() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        let repository = PostgresLoginTransactionRepository::new(pool.clone(), keyring());
        let created_at = now();
        repository
            .create(LoginTransaction::new(
                LoginTransactionId::new(LOGIN_ID)?,
                LoginTransactionPurpose::InstallationSetup,
                ProviderId::new("github")?,
                LoginTransactionFlow::device(
                    poll_binding(),
                    SecretString::new("ABCD-EFGH")?,
                    "https://github.com/login/device",
                    5_000,
                    created_at.checked_add(5)?,
                )?,
                None,
                LoginTransactionState::new(AuthSecretBytes::new(b"initial-state".to_vec())?),
                created_at,
                created_at.checked_add(600)?,
            )?)
            .await?;

        let mut gate = pool.begin().await?;
        sqlx::query("SELECT id FROM human_login_transactions WHERE id=$1 FOR UPDATE")
            .bind(Uuid::parse_str(LOGIN_ID)?)
            .execute(&mut *gate)
            .await?;
        let caller_now = now().checked_add(59)?;
        let replacement = ReplaceLoginTransactionState::new(
            access(),
            LoginTransactionVersion::new(1)?,
            LoginTransactionState::new(AuthSecretBytes::new(b"replacement-state".to_vec())?),
        )
        .next_device_poll_at(caller_now.checked_add(10)?)
        .device_poll_interval_milliseconds(10_000);
        let delayed_repository = repository.clone();
        let delayed = tokio::spawn(async move {
            delayed_repository
                .replace_state(replacement, caller_now)
                .await
        });
        if !wait_for_blocked_transaction(pool).await? {
            gate.rollback().await?;
            return Err("device replacement did not wait on its exact row lock".into());
        }
        clock.advance(1_100).await?;
        gate.commit().await?;
        assert_eq!(
            delayed.await??,
            ReplaceLoginTransactionOutcome::Replaced(LoginTransactionVersion::new(2)?)
        );
        let schedule: (i64, i64) = sqlx::query_as(
            "SELECT next_poll_at_ms,updated_at_ms FROM human_login_transactions WHERE id=$1",
        )
        .bind(Uuid::parse_str(LOGIN_ID)?)
        .fetch_one(pool)
        .await?;
        assert_eq!(schedule.0 - schedule.1, 10_000);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn replacement_final_write_cannot_cross_expiry_during_statement_delay() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        let clock = TestClock::freeze_at_database_now(pool).await?;
        let repository = PostgresLoginTransactionRepository::new(pool.clone(), keyring());
        let created_at = now();
        let transaction = LoginTransaction::new(
            LoginTransactionId::new(LOGIN_ID)?,
            LoginTransactionPurpose::InstallationSetup,
            ProviderId::new("github")?,
            LoginTransactionFlow::device(
                poll_binding(),
                SecretString::new("ABCD-EFGH")?,
                "https://github.com/login/device",
                1_000,
                created_at.checked_add(1)?,
            )?,
            None,
            LoginTransactionState::new(AuthSecretBytes::new(b"initial-state".to_vec())?),
            created_at,
            created_at.checked_add(2)?,
        )?;
        repository.create(transaction).await?;
        let expires_at_ms: i64 =
            sqlx::query_scalar("SELECT expires_at_ms FROM human_login_transactions WHERE id=$1")
                .bind(Uuid::parse_str(LOGIN_ID)?)
                .fetch_one(pool)
                .await?;
        clock
            .set(
                expires_at_ms
                    .checked_sub(1)
                    .expect("time immediately before login expiry"),
            )
            .await?;
        sqlx::query(
            r"
            CREATE FUNCTION advance_login_replacement_test_clock() RETURNS trigger AS $$
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
            CREATE TRIGGER advance_login_replacement_test_clock
            BEFORE UPDATE ON human_login_transactions
            FOR EACH STATEMENT EXECUTE FUNCTION advance_login_replacement_test_clock()
            ",
        )
        .execute(pool)
        .await?;
        let replacement = ReplaceLoginTransactionState::new(
            access(),
            LoginTransactionVersion::new(1)?,
            LoginTransactionState::new(AuthSecretBytes::new(b"late-state".to_vec())?),
        );
        assert_eq!(
            repository.replace_state(replacement, created_at).await?,
            ReplaceLoginTransactionOutcome::Expired
        );
        let unchanged: (String, i64, i32) = sqlx::query_as(
            "SELECT status,revision,poll_attempts FROM human_login_transactions WHERE id=$1",
        )
        .bind(Uuid::parse_str(LOGIN_ID)?)
        .fetch_one(pool)
        .await?;
        assert_eq!(unchanged, ("pending".to_owned(), 1, 0));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn device_state_schedule_and_slow_down_interval_share_one_revision_cas() -> TestResult {
    run_with_database(|database| async move {
        let repository = Arc::new(PostgresLoginTransactionRepository::new(
            database.pool().clone(),
            keyring(),
        ));
        let created_at = now();
        let transaction = LoginTransaction::new(
            LoginTransactionId::new(LOGIN_ID)?,
            LoginTransactionPurpose::InstallationSetup,
            ProviderId::new("github")?,
            LoginTransactionFlow::device(
                poll_binding(),
                SecretString::new("ABCD-EFGH")?,
                "https://github.com/login/device",
                5_000,
                created_at.checked_add(10)?,
            )?,
            None,
            LoginTransactionState::new(AuthSecretBytes::new(b"initial-device-state".to_vec())?),
            created_at,
            created_at.checked_add(600)?,
        )?;
        assert_eq!(
            repository.create(transaction).await?,
            CreateLoginTransactionOutcome::Created(
                LoginTransactionVersion::new(1).expect("version")
            )
        );
        assert_invalid_intervals_leave_schedule_unchanged(&repository, database.pool()).await?;
        race_replacements_and_assert_consistent_winner(&repository, database.pool()).await?;
        Ok(())
    })
    .await
}
