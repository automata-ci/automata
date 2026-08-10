mod common;

use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestResult, run_with_database, run_with_unmigrated_database};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
const MIGRATION_SQL: &str = include_str!("../migrations/0030_cli_session_activation.sql");

#[test]
fn migration_0030_is_current_only_and_encodes_the_closed_lifecycle() {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 30)
        .expect("migration 0030 is embedded");
    assert_eq!(migration.description.as_ref(), "cli session activation");
    for required in [
        "requires an empty human_sessions table",
        "lifecycle_status TEXT NOT NULL DEFAULT 'active'",
        "lifecycle_status = 'pending_activation'",
        "activation_deadline_ms - issued_at_ms BETWEEN 1 AND 300000",
        "activated_at_ms < activation_deadline_ms",
        "new CLI sessions must await activation",
        "session activation lifecycle is monotonic",
        "NEW.revision <> OLD.revision + 1",
        "human_sessions_pending_activation_expiry",
        "lifecycle_status = 'active'",
    ] {
        assert!(
            MIGRATION_SQL.contains(required),
            "missing CLI activation invariant: {required}"
        );
    }
    for prohibited in [
        "UPDATE human_sessions SET lifecycle_status",
        "COALESCE(activation",
        "legacy",
        "plaintext",
    ] {
        assert!(
            !MIGRATION_SQL.contains(prohibited),
            "migration must not infer or retain obsolete state: {prohibited}"
        );
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn populated_pre_activation_state_fails_instead_of_becoming_active() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let table_name = MIGRATOR.table_name.as_ref();
        let mut connection = database.pool().acquire().await?;
        connection.ensure_migrations_table(table_name).await?;
        for migration in MIGRATOR.iter().filter(|migration| migration.version <= 10) {
            connection.apply(table_name, migration).await?;
        }
        drop(connection);

        let principal = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ('activation-migration','Activation',100000,100000)",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO human_principals (id,created_at_ms,updated_at_ms) VALUES ($1,100000,100000)",
        )
        .bind(principal)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO human_provider_identities (
                principal_id,provider_id,provider_subject,provider_login,
                normalized_login,first_authenticated_at_ms,last_authenticated_at_ms,
                last_observed_at_ms,created_at_ms,updated_at_ms
            ) VALUES ($1,'github','42','octocat','octocat',100000,100000,100000,
                      100000,100000)
            ",
        )
        .bind(principal)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO tenant_human_memberships (tenant_id,principal_id,created_at_ms,updated_at_ms) VALUES ('activation-migration',$1,100000,100000)",
        )
        .bind(principal)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO human_sessions (
                id,tenant_id,principal_id,provider_id,provider_subject,
                session_kind,audience,token_hash,token_hash_key_id,
                authorization_revision,issued_at_ms,last_seen_at_ms,
                idle_expires_at_ms,expires_at_ms
            ) VALUES ($1,'activation-migration',$2,'github','42','browser',
                      'automata.web',$3,'migration-hmac-v1',1,100000,100000,
                      200000,300000)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(principal)
        .bind(vec![0x51_u8; 32])
        .execute(database.pool())
        .await?;

        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 30)
            .expect("migration 0030");
        let mut connection = database.pool().acquire().await?;
        let error = connection
            .apply(table_name, migration)
            .await
            .expect_err("occupied session state must fail closed");
        drop(error);
        drop(connection);
        let lifecycle_columns: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema=current_schema()
              AND table_name='human_sessions'
              AND column_name IN (
                  'lifecycle_status','activation_deadline_ms','activated_at_ms'
              )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(lifecycle_columns, 0, "failed migration must roll back exactly");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn direct_active_cli_insertion_and_lifecycle_reversal_are_rejected() -> TestResult {
    run_with_database(|database| async move {
        let principal = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms) VALUES ('activation-shape','Activation',100000,100000)",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO human_principals (id,created_at_ms,updated_at_ms) VALUES ($1,100000,100000)",
        )
        .bind(principal)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO human_provider_identities (
                principal_id,provider_id,provider_subject,provider_login,
                normalized_login,first_authenticated_at_ms,last_authenticated_at_ms,
                last_observed_at_ms,created_at_ms,updated_at_ms
            ) VALUES ($1,'github','42','octocat','octocat',100000,100000,100000,
                      100000,100000)
            ",
        )
        .bind(principal)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "INSERT INTO tenant_human_memberships (tenant_id,principal_id,created_at_ms,updated_at_ms) VALUES ('activation-shape',$1,100000,100000)",
        )
        .bind(principal)
        .execute(database.pool())
        .await?;

        let active_cli = sqlx::query(
            r"
            INSERT INTO human_sessions (
                id,tenant_id,principal_id,provider_id,provider_subject,
                session_kind,audience,token_hash,token_hash_key_id,
                authorization_revision,issued_at_ms,last_seen_at_ms,
                idle_expires_at_ms,expires_at_ms
            ) VALUES ($1,'activation-shape',$2,'github','42','cli','automata.cli',
                      $3,'shape-hmac-v1',1,100000,100000,200000,700000)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(principal)
        .bind(vec![0x61_u8; 32])
        .execute(database.pool())
        .await
        .expect_err("CLI insertion may not use the active default");
        drop(active_cli);

        let cli_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO human_sessions (
                id,tenant_id,principal_id,provider_id,provider_subject,
                session_kind,audience,token_hash,token_hash_key_id,
                authorization_revision,issued_at_ms,last_seen_at_ms,
                idle_expires_at_ms,expires_at_ms,lifecycle_status,
                activation_deadline_ms
            ) VALUES ($1,'activation-shape',$2,'github','42','cli','automata.cli',
                      $3,'shape-hmac-v1',1,100000,100000,200000,700000,
                      'pending_activation',400000)
            ",
        )
        .bind(cli_id)
        .bind(principal)
        .bind(vec![0x62_u8; 32])
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE human_sessions SET lifecycle_status='active',activated_at_ms=150000,revision=revision+1 WHERE id=$1",
        )
        .bind(cli_id)
        .execute(database.pool())
        .await?;
        let reversal = sqlx::query(
            "UPDATE human_sessions SET lifecycle_status='pending_activation',activated_at_ms=NULL,revision=revision+1 WHERE id=$1",
        )
        .bind(cli_id)
        .execute(database.pool())
        .await
        .expect_err("active CLI lifecycle is monotonic");
        drop(reversal);
        Ok(())
    })
    .await
}
