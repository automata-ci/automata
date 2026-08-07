mod support;

use std::sync::Arc;

use automata_auth::{
    machine::{MachineAuthenticationError, MachineAuthenticationEvidence, MachineIdentityVerifier},
    time::{Clock, UnixTimestamp},
};
use automata_core::{JOB_IR_SCHEMA_VERSION, RunnerId, RunnerSessionId, Sha256Digest, UnixMillis};
use automata_protocol::SUPPORTED_PROTOCOL_RANGE;
use automata_runner_auth::{
    DurableRunnerMachineAuthenticator, RunnerMachineAuthLimits, RunnerMachineDirectory,
    RunnerMachineDirectoryError,
};
use automata_runner_auth_postgres::PostgresRunnerMachineDirectory;
use automata_runner_control::{DesiredRunnerState, RunnerRegistrationAuthorizer as _};
use automata_store::{
    CommandCursor, CurrentRunnerSession, CurrentRunnerSessionRepository as _,
    HeartbeatRunnerSession, RunnerGeneration, RunnerSessionRepository as _, StoreError,
};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use support::{TestResult, run_with_database};

const EXPIRES_AT: i64 = 10_000;

#[derive(Clone, Copy, Debug)]
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now(&self) -> UnixTimestamp {
        UnixTimestamp::from_seconds(self.0)
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn exact_lookup_is_fresh_tenant_safe_and_sanitized() -> TestResult {
    run_with_database(|database| async move {
        let tenant_a = insert_tenant(database.pool(), "tenant-a").await?;
        let tenant_b = insert_tenant(database.pool(), "tenant-b").await?;
        let runner_a = insert_runner(
            database.pool(),
            &tenant_a,
            "runner-a",
            Some("github:enterprise/acme/runner-a"),
            "active",
        )
        .await?;
        let runner_b = insert_runner(
            database.pool(),
            &tenant_b,
            "runner-b",
            Some("github:enterprise/other/runner-b"),
            "draining",
        )
        .await?;
        let digest_a = Sha256Digest::from_bytes([1; 32]);
        let digest_b = Sha256Digest::from_bytes([2; 32]);
        insert_certificate(database.pool(), runner_a, digest_a, EXPIRES_AT).await?;
        insert_certificate(database.pool(), runner_b, digest_b, EXPIRES_AT + 1).await?;

        let directory = PostgresRunnerMachineDirectory::new(database.pool().clone());
        let record_a = directory
            .find_by_leaf_sha256(digest_a)
            .await?
            .expect("runner A registration");
        assert_eq!(record_a.runner_id(), runner_a);
        assert_eq!(
            record_a.external_identity().as_str(),
            "github:enterprise/acme/runner-a"
        );
        assert_eq!(record_a.generation().get(), 1);
        assert_eq!(record_a.certificate_sha256(), digest_a);
        assert_eq!(
            record_a.certificate_expires_at().as_seconds(),
            EXPIRES_AT as u64
        );
        assert_eq!(record_a.desired_state(), DesiredRunnerState::Active);

        let record_b = directory
            .find_by_leaf_sha256(digest_b)
            .await?
            .expect("runner B registration");
        assert_eq!(record_b.runner_id(), runner_b);
        assert_eq!(record_b.desired_state(), DesiredRunnerState::Draining);
        assert!(
            directory
                .find_by_leaf_sha256(Sha256Digest::from_bytes([3; 32]))
                .await?
                .is_none()
        );

        database.pool().close().await;
        let error = directory
            .find_by_leaf_sha256(digest_a)
            .await
            .expect_err("closed shared state must be unavailable");
        assert_eq!(error, RunnerMachineDirectoryError::Unavailable);
        assert_eq!(error.to_string(), "runner machine directory is unavailable");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn rotation_revocation_and_global_identity_constraints_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let tenant_a = insert_tenant(database.pool(), "rotation-a").await?;
        let tenant_b = insert_tenant(database.pool(), "rotation-b").await?;
        let runner_a = insert_runner(
            database.pool(),
            &tenant_a,
            "rotation-a",
            Some("machine:globally-unique"),
            "active",
        )
        .await?;
        let runner_b = insert_runner(
            database.pool(),
            &tenant_b,
            "rotation-b",
            Some("machine:runner-b"),
            "active",
        )
        .await?;
        let old = Sha256Digest::from_bytes([10; 32]);
        let new = Sha256Digest::from_bytes([11; 32]);
        insert_certificate(database.pool(), runner_a, old, EXPIRES_AT).await?;
        insert_certificate(database.pool(), runner_a, new, EXPIRES_AT + 100).await?;
        let directory = PostgresRunnerMachineDirectory::new(database.pool().clone());
        assert!(directory.find_by_leaf_sha256(old).await?.is_some());
        assert!(directory.find_by_leaf_sha256(new).await?.is_some());

        sqlx::query(
            "UPDATE runner_machine_certificates SET revoked_at_seconds = 9000 WHERE leaf_sha256 = $1",
        )
        .bind(old.as_bytes().as_slice())
        .execute(database.pool())
        .await?;
        assert!(directory.find_by_leaf_sha256(old).await?.is_none());
        assert!(directory.find_by_leaf_sha256(new).await?.is_some());
        let reassignment = sqlx::query(
            "UPDATE runner_machine_certificates SET runner_id = $2 WHERE leaf_sha256 = $1",
        )
        .bind(new.as_bytes().as_slice())
        .bind(runner_b.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("registered leaf ownership must be immutable");
        assert_constraint(
            &reassignment,
            "runner_machine_certificates_authority_immutable",
        );
        let unrevoke = sqlx::query(
            "UPDATE runner_machine_certificates SET revoked_at_seconds = NULL WHERE leaf_sha256 = $1",
        )
        .bind(old.as_bytes().as_slice())
        .execute(database.pool())
        .await
        .expect_err("revocation must be one-way");
        assert_constraint(
            &unrevoke,
            "runner_machine_certificates_revocation_write_once",
        );
        let rewrite_revocation = sqlx::query(
            "UPDATE runner_machine_certificates SET revoked_at_seconds = 9001 WHERE leaf_sha256 = $1",
        )
        .bind(old.as_bytes().as_slice())
        .execute(database.pool())
        .await
        .expect_err("an existing revocation timestamp must be immutable");
        assert_constraint(
            &rewrite_revocation,
            "runner_machine_certificates_revocation_write_once",
        );

        let cross_runner = sqlx::query(
            "INSERT INTO runner_machine_certificates (leaf_sha256, runner_id, expires_at_seconds) VALUES ($1, $2, $3)",
        )
        .bind(new.as_bytes().as_slice())
        .bind(runner_b.as_uuid())
        .bind(EXPIRES_AT)
        .execute(database.pool())
        .await
        .expect_err("one leaf digest must never authorize two runners");
        assert_constraint(&cross_runner, "runner_machine_certificates_pkey");

        let duplicate_identity = insert_runner(
            database.pool(),
            &tenant_b,
            "duplicate-identity",
            Some("machine:globally-unique"),
            "active",
        )
        .await
        .expect_err("external machine identity must be unique across tenants");
        assert_constraint(&duplicate_identity, "runners_external_identity_unique");

        let late_revocation = sqlx::query(
            "UPDATE runner_machine_certificates SET revoked_at_seconds = expires_at_seconds + 1 WHERE leaf_sha256 = $1",
        )
        .bind(new.as_bytes().as_slice())
        .execute(database.pool())
        .await
        .expect_err("revocation time must fall within the certificate lifetime");
        assert_constraint(
            &late_revocation,
            "runner_machine_certificates_revocation_monotonic",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn corrupt_authority_rows_are_never_downgraded_to_unknown() -> TestResult {
    run_with_database(|database| async move {
        let tenant = insert_tenant(database.pool(), "corrupt").await?;
        let runner = insert_runner(database.pool(), &tenant, "legacy", None, "active").await?;
        let digest = Sha256Digest::from_bytes([20; 32]);
        insert_certificate(database.pool(), runner, digest, EXPIRES_AT).await?;
        let directory = PostgresRunnerMachineDirectory::new(database.pool().clone());
        assert_eq!(
            directory.find_by_leaf_sha256(digest).await,
            Err(RunnerMachineDirectoryError::Corrupt),
            "a certificate attached to an unmapped legacy runner is corrupt authority"
        );

        sqlx::query("UPDATE runners SET external_identity = 'machine:legacy' WHERE id = $1")
            .bind(runner.as_uuid())
            .execute(database.pool())
            .await?;
        sqlx::query(
            "ALTER TABLE runners DROP CONSTRAINT runners_external_identity_shape",
        )
        .execute(database.pool())
        .await?;
        sqlx::query("UPDATE runners SET external_identity = repeat('x', 256) WHERE id = $1")
            .bind(runner.as_uuid())
            .execute(database.pool())
            .await?;
        assert_eq!(
            directory.find_by_leaf_sha256(digest).await,
            Err(RunnerMachineDirectoryError::Corrupt),
            "oversized durable text must be rejected before adapter allocation"
        );
        sqlx::query("UPDATE runners SET external_identity = 'machine:legacy' WHERE id = $1")
            .bind(runner.as_uuid())
            .execute(database.pool())
            .await?;
        // This fixture deliberately models durable corruption after bypassing
        // both database guards. Normal writers cannot alter certificate
        // lifetimes because the authority row is immutable.
        sqlx::query(
            "DROP TRIGGER runner_machine_certificates_authority_immutable ON runner_machine_certificates",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE runner_machine_certificates DROP CONSTRAINT runner_machine_certificates_expiration_positive",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "UPDATE runner_machine_certificates SET expires_at_seconds = 0 WHERE leaf_sha256 = $1",
        )
        .bind(digest.as_bytes().as_slice())
        .execute(database.pool())
        .await?;
        assert_eq!(
            directory.find_by_leaf_sha256(digest).await,
            Err(RunnerMachineDirectoryError::Corrupt)
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn fresh_authorization_tracks_drain_disable_expiration_and_revocation() -> TestResult {
    run_with_database(|database| async move {
        let tenant = insert_tenant(database.pool(), "state").await?;
        let runner = insert_runner(
            database.pool(),
            &tenant,
            "state-runner",
            Some("machine:state-runner"),
            "active",
        )
        .await?;
        let leaf = b"tls-validated-leaf-der".to_vec();
        let digest = Sha256Digest::from_bytes(Sha256::digest(&leaf).into());
        insert_certificate(database.pool(), runner, digest, 200).await?;
        let session_id = insert_live_session(database.pool(), runner).await?;

        let directory: Arc<dyn RunnerMachineDirectory> = Arc::new(
            PostgresRunnerMachineDirectory::new(database.pool().clone()),
        );
        let authenticator = DurableRunnerMachineAuthenticator::new(
            directory,
            Arc::new(FixedClock(100)),
            RunnerMachineAuthLimits::default(),
        );
        let evidence = MachineAuthenticationEvidence::new(vec![leaf])?;
        let machine = authenticator.authenticate(&evidence).await?;
        let active = authenticator
            .authorize(&machine)
            .await?
            .expect("active registration");
        assert_eq!(active.desired_state(), DesiredRunnerState::Active);

        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(runner.as_uuid())
            .execute(database.pool())
            .await?;
        let draining = authenticator
            .authorize(&machine)
            .await?
            .expect("draining remains a registered identity");
        assert_eq!(draining.desired_state(), DesiredRunnerState::Draining);
        let current = CurrentRunnerSession::new(
            runner,
            RunnerGeneration::new(1)?,
            session_id,
        );
        assert!(
            database
                .store()
                .resolve_current_session(current)
                .await?
                .is_some(),
            "draining preserves the observed-online current session"
        );
        let fence = database
            .store()
            .resolve_current_session(current)
            .await?
            .expect("current fence");
        database
            .store()
            .heartbeat_session(HeartbeatRunnerSession::new(
                fence,
                CommandCursor::initial(),
                UnixMillis::new(101),
            ))
            .await?;

        sqlx::query("UPDATE runners SET desired_state = 'disabled' WHERE id = $1")
            .bind(runner.as_uuid())
            .execute(database.pool())
            .await?;
        let disabled = authenticator
            .authorize(&machine)
            .await?
            .expect("directory reports state for the handler to deny");
        assert_eq!(disabled.desired_state(), DesiredRunnerState::Disabled);
        assert!(database.store().resolve_current_session(current).await?.is_none());
        assert!(matches!(
            database
                .store()
                .heartbeat_session(HeartbeatRunnerSession::new(
                    fence,
                    CommandCursor::initial(),
                    UnixMillis::new(102),
                ))
                .await,
            Err(StoreError::RunnerDisabled(id)) if id == runner
        ));

        sqlx::query("UPDATE runners SET desired_state = 'active' WHERE id = $1")
            .bind(runner.as_uuid())
            .execute(database.pool())
            .await?;
        let expired_authenticator = DurableRunnerMachineAuthenticator::new(
            Arc::new(PostgresRunnerMachineDirectory::new(database.pool().clone())),
            Arc::new(FixedClock(201)),
            RunnerMachineAuthLimits::default(),
        );
        assert_eq!(
            expired_authenticator.authenticate(&evidence).await,
            Err(MachineAuthenticationError::Expired)
        );

        sqlx::query(
            "UPDATE runner_machine_certificates SET revoked_at_seconds = 150 WHERE leaf_sha256 = $1",
        )
        .bind(digest.as_bytes().as_slice())
        .execute(database.pool())
        .await?;
        assert!(authenticator.authorize(&machine).await?.is_none());
        Ok(())
    })
    .await
}

async fn insert_tenant(pool: &PgPool, prefix: &str) -> TestResult<String> {
    let tenant = format!("{prefix}-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, $2, 1, 1)",
    )
    .bind(&tenant)
    .bind(prefix)
    .execute(pool)
    .await?;
    Ok(tenant)
}

async fn insert_runner(
    pool: &PgPool,
    tenant: &str,
    name: &str,
    external_identity: Option<&str>,
    desired_state: &str,
) -> Result<RunnerId, sqlx::Error> {
    let runner = RunnerId::new();
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots,
            status, desired_state, external_identity, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, $3, '{}', 1, 'online', $4, $5, 1, 1)
        ",
    )
    .bind(runner.as_uuid())
    .bind(tenant)
    .bind(name)
    .bind(desired_state)
    .bind(external_identity)
    .execute(pool)
    .await?;
    Ok(runner)
}

async fn insert_certificate(
    pool: &PgPool,
    runner: RunnerId,
    digest: Sha256Digest,
    expires_at_seconds: i64,
) -> TestResult {
    sqlx::query(
        "INSERT INTO runner_machine_certificates (leaf_sha256, runner_id, expires_at_seconds) VALUES ($1, $2, $3)",
    )
    .bind(digest.as_bytes().as_slice())
    .bind(runner.as_uuid())
    .bind(expires_at_seconds)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_live_session(pool: &PgPool, runner: RunnerId) -> TestResult<RunnerSessionId> {
    let session = RunnerSessionId::new();
    sqlx::query("UPDATE runners SET session_epoch = 1 WHERE id = $1")
        .bind(runner.as_uuid())
        .execute(pool)
        .await?;
    sqlx::query(
        r"
        INSERT INTO runner_sessions (
            id, runner_id, protocol_version, job_ir_schema, capability_snapshot,
            connected_at_ms, heartbeat_at_ms, runner_generation, session_epoch
        ) VALUES ($1, $2, $3, $4, '{}', 1, 1, 1, 1)
        ",
    )
    .bind(session.as_uuid())
    .bind(runner.as_uuid())
    .bind(i32::from(SUPPORTED_PROTOCOL_RANGE.max().get()))
    .bind(i32::from(JOB_IR_SCHEMA_VERSION))
    .execute(pool)
    .await?;
    Ok(session)
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(actual, Some(expected), "unexpected database error: {error}");
}
