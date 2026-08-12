#[allow(dead_code)]
mod common;

use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_store::{
    AcceptProviderDelivery, AdmissionObject, BeginGithubCheckRunCreate, BindGithubCheckRun,
    BindGithubCheckSuite, BlockGithubCheckProjectionForCredentialRejection,
    ClaimGithubCheckProjection, ClaimedGithubCheckProjection, CompleteGithubCheckProjection,
    GithubCheckAppId, GithubCheckDesiredProjection, GithubCheckHeadSha, GithubCheckName,
    GithubCheckProjectionAction, GithubCheckProjectionClaimFence, GithubCheckProjectionOutbox as _,
    GithubCheckProjectionWorkerId, GithubCheckRunBindingFence, GithubCheckRunCreateFence,
    GithubCheckRunId, GithubCheckStoreError, GithubCheckSubjectIdentity, GithubCheckSubjectKey,
    GithubCheckSubjectReceipt, GithubCheckSubjectRepository as _, GithubCheckSubjectTarget,
    GithubCheckSuiteId, GithubCheckTerminalCause, GithubCheckTerminalizationRepository as _,
    GithubRepositoryName, LinkGithubCheckWorkflowRun, ObjectKey, ProviderConnectionId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryVisibility,
    RegisterGithubCheckSubject, ReleaseUnissuedGithubCheckRunCreate, RepositoryId,
    ResolveGithubCheckRunCreate, StartGithubCheckProjection, TenantScope, TerminalizeGithubCheck,
};
use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_unmigrated_database};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const GITHUB_REPOSITORY_ID: u64 = 202;
const GITHUB_INSTALLATION_ID: u64 = 101;
const GITHUB_APP_ID: u64 = 303;
const HEAD_SHA: [u8; 20] = [9; 20];
const CLAIM_MILLIS: i64 = 200;

async fn apply_credential_rejection_migration(connection: &mut sqlx::PgConnection) -> TestResult {
    // Migration 0053 also retires incompatible authorities against the 0035
    // manifest tables. This 0029-focused fixture has no manifest candidates;
    // empty connection-local tables let it execute the exact migration while
    // retirement lifecycle coverage remains in the dedicated 0053 tests.
    sqlx::query(
        r"
        CREATE TEMPORARY TABLE github_provider_manifest_revisions (
            tenant_id TEXT NOT NULL,
            repository_id UUID NOT NULL,
            provider_connection_id UUID NOT NULL,
            manifest_revision BIGINT NOT NULL,
            manifest_digest BYTEA NOT NULL,
            provider_installation_id BIGINT NOT NULL,
            github_repository_id BIGINT NOT NULL,
            github_repository_name TEXT NOT NULL,
            github_app_id BIGINT NOT NULL,
            github_app_client_id TEXT NOT NULL,
            github_app_jwt_issuer_kind TEXT NOT NULL,
            app_key_spki_sha256 BYTEA NOT NULL,
            app_configuration_revision BIGINT NOT NULL,
            policy_revision BIGINT NOT NULL,
            repository_source_authentication TEXT NOT NULL
        )
        ",
    )
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        r"
        CREATE TEMPORARY TABLE github_provider_manifest_current (
            tenant_id TEXT NOT NULL,
            repository_id UUID NOT NULL,
            provider_connection_id UUID NOT NULL,
            manifest_revision BIGINT NOT NULL,
            manifest_digest BYTEA NOT NULL
        )
        ",
    )
    .execute(&mut *connection)
    .await?;
    let credential_rejection = MIGRATOR
        .iter()
        .find(|migration| migration.version == 53)
        .expect("credential-rejection migration");
    connection
        .apply(MIGRATOR.table_name.as_ref(), credential_rejection)
        .await?;
    sqlx::query("DROP TABLE github_provider_manifest_current, github_provider_manifest_revisions")
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn apply_checks_migrations(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR.iter().filter(|migration| migration.version < 35) {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    apply_credential_rejection_migration(&mut connection).await?;
    // These focused 0029 lifecycle tests intentionally stop before the 0035
    // current-only cutover. Model only the later immutable selector projection
    // consumed by the current outbox adapter; full 0037 parity is covered by
    // `postgres_github_subject_evidence` against the complete migration chain.
    sqlx::query(
        r"
        CREATE TABLE github_provider_delivery_evidence (
            github_check_subject_id UUID PRIMARY KEY,
            provider_delivery_id UUID NOT NULL,
            tenant_id TEXT NOT NULL,
            repository_id UUID NOT NULL,
            checks_authority_id UUID NOT NULL,
            checks_authority_identity_digest BYTEA NOT NULL,
            checks_authority_app_configuration_revision BIGINT NOT NULL,
            checks_authority_policy_revision BIGINT NOT NULL
        )
        ",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        CREATE TABLE github_schedule_check_evidence (
            github_check_subject_id UUID PRIMARY KEY,
            schedule_fire_id UUID NOT NULL,
            tenant_id TEXT NOT NULL,
            repository_id UUID NOT NULL,
            provider_connection_id UUID NOT NULL,
            checks_authority_id UUID NOT NULL,
            checks_authority_identity_digest BYTEA NOT NULL,
            checks_authority_app_configuration_revision BIGINT NOT NULL,
            checks_authority_policy_revision BIGINT NOT NULL
        )
        ",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        CREATE FUNCTION checks_test_pin_authority() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.origin_kind <> 'provider_delivery' THEN
                RETURN NEW;
            END IF;
            INSERT INTO github_provider_delivery_evidence (
                github_check_subject_id, provider_delivery_id, tenant_id,
                repository_id, checks_authority_id,
                checks_authority_identity_digest,
                checks_authority_app_configuration_revision,
                checks_authority_policy_revision
            ) VALUES (
                NEW.id, NEW.provider_delivery_id, NEW.tenant_id,
                NEW.repository_id,
                '00000000-0000-4000-8000-00000000c001'::UUID,
                decode(repeat('09', 32), 'hex'), 1, 1
            );
            RETURN NEW;
        END;
        $$
        ",
    )
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        CREATE TRIGGER checks_test_pin_authority
        AFTER INSERT ON github_check_subjects
        FOR EACH ROW EXECUTE FUNCTION checks_test_pin_authority()
        ",
    )
    .execute(database.pool())
    .await?;
    Ok(())
}

struct Fixture {
    tenant: TenantScope,
    repository_id: RepositoryId,
    delivery_id: automata_ci_store::ProviderDeliveryId,
    connection_id: ProviderConnectionId,
    run_id: RunId,
    wrong_sha_run_id: RunId,
}

async fn seed_fixture(database: &TestDatabase) -> TestResult<Fixture> {
    let tenant_text = format!("checks-{}", Uuid::new_v4().simple());
    let tenant = TenantScope::from_authenticated_tenant_id(tenant_text.clone())?;
    let repository_uuid = Uuid::new_v4();
    let workflow_uuid = Uuid::new_v4();
    let snapshot_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let wrong_run_uuid = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants VALUES ($1, 'Checks', 1, 1)")
        .bind(&tenant_text)
        .execute(database.pool())
        .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', $3, 'automata-ci', 'automata', 1, 1)
        ",
    )
    .bind(repository_uuid)
    .bind(&tenant_text)
    .bind(GITHUB_REPOSITORY_ID.to_string())
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, '.github/workflows/ci.yml', 1, 1)
        ",
    )
    .bind(workflow_uuid)
    .bind(repository_uuid)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key,
            frontend_schema, created_at_ms
        ) VALUES ($1, $2, $3, 'checks/source', 1, 1)
        ",
    )
    .bind(snapshot_uuid)
    .bind(workflow_uuid)
    .bind([7_u8; 32].as_slice())
    .execute(database.pool())
    .await?;
    for (run, number, sha) in [
        (run_uuid, 1_i64, HEAD_SHA),
        (wrong_run_uuid, 2_i64, [8_u8; 20]),
    ] {
        sqlx::query(
            r"
            INSERT INTO workflow_runs (
                id, repository_id, workflow_id, snapshot_id, run_number,
                event_name, event_object_key, head_sha, status,
                created_at_ms, updated_at_ms
            ) VALUES ($1, $2, $3, $4, $5, 'push', $6, $7, 'queued', 2, 2)
            ",
        )
        .bind(run)
        .bind(repository_uuid)
        .bind(workflow_uuid)
        .bind(snapshot_uuid)
        .bind(number)
        .bind(format!("checks/event/{number}"))
        .bind(sha.as_slice())
        .execute(database.pool())
        .await?;
    }

    let connection_id = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
    let delivery_id = accept_delivery(database, tenant.clone(), connection_id).await?;
    Ok(Fixture {
        tenant,
        repository_id: RepositoryId::from_uuid(repository_uuid),
        delivery_id,
        connection_id,
        run_id: RunId::from_uuid(run_uuid),
        wrong_sha_run_id: RunId::from_uuid(wrong_run_uuid),
    })
}

async fn accept_delivery(
    database: &TestDatabase,
    tenant: TenantScope,
    connection_id: ProviderConnectionId,
) -> TestResult<automata_ci_store::ProviderDeliveryId> {
    let delivery_identity = ProviderDeliveryIdentity::new(
        tenant,
        "github",
        connection_id,
        ProviderInstallationId::new(GITHUB_INSTALLATION_ID)?,
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(GITHUB_REPOSITORY_ID)?,
            ProviderRepositoryVisibility::Private,
            "automata-ci/automata",
        )?,
        "checks-delivery",
    )?;
    let raw_event = AdmissionObject::new(
        Sha256Digest::from_bytes([5; 32]),
        ObjectKey::new("checks/events/push")?,
        256,
        "application/json",
    )?;
    Ok(database
        .store()
        .accept_provider_delivery(AcceptProviderDelivery::new(
            delivery_identity,
            Sha256Digest::from_bytes([4; 32]),
            raw_event,
            UnixMillis::new(10),
        )?)
        .await?
        .id())
}

fn registration(fixture: &Fixture, key: &str, name: &str, at: i64) -> RegisterGithubCheckSubject {
    let identity = GithubCheckSubjectIdentity::new(
        fixture.tenant.clone(),
        fixture.repository_id,
        fixture.delivery_id,
        GithubCheckSubjectKey::new(key).expect("subject key"),
        fixture.connection_id,
        ProviderInstallationId::new(GITHUB_INSTALLATION_ID).expect("installation"),
        ProviderRepositoryId::new(GITHUB_REPOSITORY_ID).expect("repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        GithubCheckAppId::new(GITHUB_APP_ID).expect("App ID"),
        GithubCheckHeadSha::new(HEAD_SHA).expect("head SHA"),
        GithubCheckName::new(name).expect("Check name"),
    )
    .expect("subject identity");
    RegisterGithubCheckSubject::new(identity, UnixMillis::new(at)).expect("registration")
}

fn worker() -> GithubCheckProjectionWorkerId {
    GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4()).expect("worker ID")
}

fn claim_request_at(
    fixture: &Fixture,
    observed_at: i64,
    duration: i64,
) -> ClaimGithubCheckProjection {
    ClaimGithubCheckProjection::new(
        fixture.connection_id,
        worker(),
        UnixMillis::new(observed_at),
        UnixMillis::new(observed_at + duration),
    )
    .expect("claim request")
}

async fn claim_request(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult<ClaimGithubCheckProjection> {
    Ok(claim_request_at(
        fixture,
        database_now_ms(database).await?,
        CLAIM_MILLIS,
    ))
}

async fn claim_projection(
    database: &TestDatabase,
    fixture: &Fixture,
) -> TestResult<Option<ClaimedGithubCheckProjection>> {
    database
        .store()
        .claim_github_check_projection(claim_request(database, fixture).await?)
        .await
        .map_err(Into::into)
}

fn live_observation(claimed: &ClaimedGithubCheckProjection) -> UnixMillis {
    UnixMillis::new(claimed.claimed_at().get() + 1)
}

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}

async fn wait_until_database(database: &TestDatabase, target: UnixMillis) -> TestResult {
    while database_now_ms(database).await? < target.get() {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    Ok(())
}

async fn github_check_outbox_snapshot(
    database: &TestDatabase,
    subject_id: automata_ci_store::GithubCheckSubjectId,
) -> TestResult<String> {
    Ok(sqlx::query_scalar(
        r"
        SELECT row_to_json(outbox)::text
        FROM github_check_projection_outbox AS outbox
        WHERE outbox.subject_id = $1
        ",
    )
    .bind(subject_id.as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn assert_credential_block_rejected_without_mutation(
    database: &TestDatabase,
    subject_id: automata_ci_store::GithubCheckSubjectId,
    request: BlockGithubCheckProjectionForCredentialRejection,
    before: &str,
) -> TestResult {
    assert!(matches!(
        database
            .store()
            .block_github_check_projection_for_credential_rejection(request)
            .await,
        Err(GithubCheckStoreError::ClaimRejected)
    ));
    assert_eq!(
        github_check_outbox_snapshot(database, subject_id).await?,
        before,
        "a rejected credential block must not mutate durable state"
    );
    Ok(())
}

async fn assert_credential_rejection_blocked_state(
    database: &TestDatabase,
    fixture: &Fixture,
    receipt: &GithubCheckSubjectReceipt,
    create_fence: GithubCheckRunCreateFence,
    suite: GithubCheckSuiteId,
    blocked_at: UnixMillis,
) -> TestResult {
    let row: (String, String, bool, bool, bool, i64) = sqlx::query_as(
        r"
        SELECT state, blocked_reason,
               claim_owner_id IS NULL
                   AND claim_action IS NULL
                   AND claimed_desired_revision IS NULL
                   AND claimed_desired_state IS NULL
                   AND claimed_desired_conclusion IS NULL
                   AND claimed_at_ms IS NULL
                   AND claim_expires_at_ms IS NULL AS claim_cleared,
               next_attempt_at_ms IS NULL
                   AND last_failure_kind IS NULL AS retry_cleared,
               COALESCE(
                   external_suite_id = $2
                   AND external_run_id IS NULL
                   AND external_bound_at_ms IS NULL
                   AND create_owner_id = $3
                   AND create_fence = $4
                   AND create_started_at_ms = $5
                   AND create_issue_expires_at_ms = $6
                   AND reconcile_not_before_ms = $7
                   AND next_reconcile_at_ms = $7,
                   FALSE
               ) AS external_and_create_evidence_preserved,
               state_updated_at_ms
        FROM github_check_projection_outbox
        WHERE subject_id = $1
        ",
    )
    .bind(receipt.subject_id().as_uuid())
    .bind(i64::try_from(suite.get()).expect("suite ID fits BIGINT"))
    .bind(create_fence.claim().owner().as_uuid())
    .bind(i64::try_from(create_fence.claim().fence()).expect("create fence fits BIGINT"))
    .bind(create_fence.started_at().get())
    .bind(create_fence.issue_expires_at().get())
    .bind(create_fence.reconcile_not_before().get())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        row,
        (
            "blocked".into(),
            "credential_rejected".into(),
            true,
            true,
            true,
            blocked_at.get(),
        )
    );
    assert!(
        claim_projection(database, fixture).await?.is_none(),
        "a credential-rejected projection must never be reclaimed"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn pre_admission_subject_projects_through_created_run_and_terminal_state() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let request = registration(&fixture, ".github/workflows/ci.yml", "Automata / CI", 100);
        let registered = database
            .store()
            .register_github_check_subject(request.clone())
            .await?;
        assert_eq!(registered.desired(), GithubCheckDesiredProjection::Queued);
        assert_eq!(registered.workflow_run_id(), None);
        assert_eq!(
            registered.external_id(),
            format!("automata-check:{}", registered.subject_id().as_uuid())
        );
        assert_eq!(
            database
                .store()
                .register_github_check_subject(request)
                .await?,
            registered
        );

        assert!(matches!(
            database
                .store()
                .register_github_check_subject(registration(
                    &fixture,
                    ".github/workflows/ci.yml",
                    "Changed",
                    100,
                ))
                .await,
            Err(GithubCheckStoreError::ReplayConflict)
        ));
        let target = GithubCheckSubjectTarget::new(fixture.tenant.clone(), registered.subject_id());
        assert!(matches!(
            database
                .store()
                .link_github_check_workflow_run(LinkGithubCheckWorkflowRun::new(
                    target.clone(),
                    fixture.wrong_sha_run_id,
                    UnixMillis::new(110),
                )?)
                .await,
            Err(GithubCheckStoreError::AuthorityRejected)
        ));
        let linked = database
            .store()
            .link_github_check_workflow_run(LinkGithubCheckWorkflowRun::new(
                target.clone(),
                fixture.run_id,
                UnixMillis::new(120),
            )?)
            .await?;
        assert_eq!(linked.workflow_run_id(), Some(fixture.run_id));

        drive_queued_create(&database, &fixture, &target).await?;
        drive_in_progress_and_terminal(&database, &fixture, &target).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn terminal_workflow_run_rejects_new_check_link_but_preserves_exact_replay() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let linked = database
            .store()
            .register_github_check_subject(registration(
                &fixture,
                ".github/workflows/linked.yml",
                "Automata / Linked",
                100,
            ))
            .await?;
        let late = database
            .store()
            .register_github_check_subject(registration(
                &fixture,
                ".github/workflows/late.yml",
                "Automata / Late",
                101,
            ))
            .await?;
        let linked_target =
            GithubCheckSubjectTarget::new(fixture.tenant.clone(), linked.subject_id());
        let link = LinkGithubCheckWorkflowRun::new(
            linked_target.clone(),
            fixture.run_id,
            UnixMillis::new(110),
        )?;
        let linked_receipt = database
            .store()
            .link_github_check_workflow_run(link.clone())
            .await?;

        let mut finalizer = database.pool().begin().await?;
        let finalizer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *finalizer)
            .await?;
        sqlx::query("SELECT id FROM workflow_runs WHERE id = $1 FOR UPDATE")
            .bind(fixture.run_id.as_uuid())
            .fetch_one(&mut *finalizer)
            .await?;
        let late_store = database.store().clone();
        let late_link = LinkGithubCheckWorkflowRun::new(
            GithubCheckSubjectTarget::new(fixture.tenant.clone(), late.subject_id()),
            fixture.run_id,
            UnixMillis::new(121),
        )?;
        let waiting_link =
            tokio::spawn(async move { late_store.link_github_check_workflow_run(late_link).await });
        let mut observed_waiter = false;
        for _ in 0..100 {
            observed_waiter = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity AS activity
                    WHERE $1 = ANY(pg_blocking_pids(activity.pid))
                      AND activity.query LIKE '%WITH locked_run AS MATERIALIZED%'
                )
                ",
            )
            .bind(finalizer_pid)
            .fetch_one(database.pool())
            .await?;
            if observed_waiter {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(observed_waiter, "link did not wait on the exact run lock");
        sqlx::query(
            "UPDATE workflow_runs SET status = 'completed', updated_at_ms = 120 WHERE id = $1",
        )
        .bind(fixture.run_id.as_uuid())
        .execute(&mut *finalizer)
        .await?;
        finalizer.commit().await?;

        assert!(matches!(
            waiting_link.await?,
            Err(GithubCheckStoreError::AuthorityRejected)
        ));
        assert_eq!(
            database
                .store()
                .link_github_check_workflow_run(link)
                .await?,
            linked_receipt
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn subject_without_immutable_authority_evidence_is_not_claimable() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let registered = database
            .store()
            .register_github_check_subject(registration(
                &fixture,
                ".github/workflows/ci.yml",
                "Automata / CI",
                100,
            ))
            .await?;
        sqlx::query(
            "DELETE FROM github_provider_delivery_evidence \
             WHERE github_check_subject_id = $1",
        )
        .bind(registered.subject_id().as_uuid())
        .execute(database.pool())
        .await?;

        assert!(
            claim_projection(&database, &fixture).await?.is_none(),
            "a Check without its immutable 0037 selector evidence must remain unclaimable"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One lifecycle keeps the rerun authority fence auditable.
async fn rerun_origin_claim_decodes_and_reconciles_under_its_exact_authority() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let subject_id = Uuid::new_v4();
        let rerun_run_id = Uuid::new_v4();
        let mut transaction = database.pool().begin().await?;
        sqlx::query(
            "ALTER TABLE github_check_subjects DISABLE TRIGGER github_check_subjects_00_canonical_name",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "ALTER TABLE github_check_subjects DISABLE TRIGGER github_check_subjects_insert_guard",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO github_check_subjects (
                id, tenant_id, repository_id, provider_delivery_id,
                origin_kind, schedule_fire_id, workflow_rerun_run_id,
                subject_key, provider_connection_id,
                provider_installation_id, github_repository_id,
                github_repository_name, github_app_id, head_sha, check_name,
                external_id, created_at_ms, desired_updated_at_ms
            ) VALUES (
                $1, $2, $3, NULL, 'workflow_rerun', NULL, $4,
                '.github/workflows/ci.yml', $5, $6, $7,
                'automata-ci/automata', $8, $9, 'Automata / rerun',
                $10, 100, 100
            )
            ",
        )
        .bind(subject_id)
        .bind(fixture.tenant.as_str())
        .bind(fixture.repository_id.as_uuid())
        .bind(rerun_run_id)
        .bind(fixture.connection_id.as_uuid())
        .bind(i64::try_from(GITHUB_INSTALLATION_ID)?)
        .bind(i64::try_from(GITHUB_REPOSITORY_ID)?)
        .bind(i64::try_from(GITHUB_APP_ID)?)
        .bind(HEAD_SHA.as_slice())
        .bind(format!("automata-check:{subject_id}"))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "ALTER TABLE github_check_subjects ENABLE TRIGGER github_check_subjects_insert_guard",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "ALTER TABLE github_check_subjects ENABLE TRIGGER github_check_subjects_00_canonical_name",
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        sqlx::query(
            r"
            INSERT INTO workflow_rerun_check_evidence (
                github_check_subject_id, run_id, tenant_id, repository_id,
                provider_connection_id, checks_authority_id,
                checks_authority_identity_digest,
                checks_authority_app_configuration_revision,
                checks_authority_policy_revision
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,1,1)
            ",
        )
        .bind(subject_id)
        .bind(rerun_run_id)
        .bind(fixture.tenant.as_str())
        .bind(fixture.repository_id.as_uuid())
        .bind(fixture.connection_id.as_uuid())
        .bind(Uuid::from_u128(0x00000000_0000_4000_8000_00000000c001))
        .bind([9_u8; 32].as_slice())
        .execute(database.pool())
        .await?;

        let claimed = claim_projection(&database, &fixture)
            .await?
            .ok_or("rerun-origin projection was not claimable")?;
        assert_eq!(claimed.claim().subject_id().as_uuid(), subject_id);
        assert_eq!(
            claimed.identity().rerun_run_id(),
            Some(RunId::from_uuid(rerun_run_id))
        );
        assert_eq!(claimed.identity().delivery_id(), None);
        assert_eq!(claimed.identity().schedule_fire_id(), None);
        assert_eq!(claimed.action(), GithubCheckProjectionAction::EnsureSuite);
        assert_eq!(
            claimed.checks_authority().authority_id().as_uuid(),
            Uuid::from_u128(0x00000000_0000_4000_8000_00000000c001)
        );
        let replay = database
            .store()
            .bind_github_check_suite(BindGithubCheckSuite::new(
                claimed.claim(),
                GithubCheckSuiteId::new(901)?,
                live_observation(&claimed),
            )?)
            .await?;
        assert_eq!(replay.subject_id().as_uuid(), subject_id);
        let next = claim_projection(&database, &fixture)
            .await?
            .ok_or("rerun-origin create preparation was not claimable")?;
        assert_eq!(next.claim().subject_id().as_uuid(), subject_id);
        assert_eq!(next.action(), GithubCheckProjectionAction::PrepareRunCreate);
        assert_eq!(
            next.identity().rerun_run_id(),
            Some(RunId::from_uuid(rerun_run_id))
        );
        Ok(())
    })
    .await
}

async fn drive_queued_create(
    database: &TestDatabase,
    fixture: &Fixture,
    target: &GithubCheckSubjectTarget,
) -> TestResult {
    let ensure = claim_projection(database, fixture)
        .await?
        .expect("suite work");
    assert_eq!(ensure.action(), GithubCheckProjectionAction::EnsureSuite);
    assert_eq!(
        ensure.identity().github_repository_name().as_str(),
        "automata-ci/automata"
    );
    assert_eq!(
        ensure.checks_authority().authority_id().as_uuid(),
        Uuid::from_u128(0x00000000_0000_4000_8000_00000000c001)
    );
    assert_eq!(
        ensure.checks_authority().identity_digest(),
        Sha256Digest::from_bytes([9; 32])
    );
    assert_eq!(
        ensure.checks_authority().app_configuration_revision().get(),
        1
    );
    assert_eq!(ensure.checks_authority().policy_revision().get(), 1);
    let suite = GithubCheckSuiteId::new(401)?;
    database
        .store()
        .bind_github_check_suite(BindGithubCheckSuite::new(
            ensure.claim(),
            suite,
            live_observation(&ensure),
        )?)
        .await?;

    let prepare = claim_projection(database, fixture)
        .await?
        .expect("create preparation");
    assert_eq!(
        prepare.action(),
        GithubCheckProjectionAction::PrepareRunCreate
    );
    let create_fence = database
        .store()
        .begin_github_check_run_create(BeginGithubCheckRunCreate::new(
            &prepare,
            live_observation(&prepare),
            UnixMillis::new(prepare.expires_at().get() + 10),
        )?)
        .await?;
    let receipt = database
        .store()
        .bind_github_check_run(BindGithubCheckRun::new(
            GithubCheckRunBindingFence::Create(create_fence),
            suite,
            GithubCheckRunId::new(501)?,
            UnixMillis::new(create_fence.started_at().get() + 1),
        )?)
        .await?;
    assert_eq!(receipt.desired(), GithubCheckDesiredProjection::Queued);
    let state: String = sqlx::query_scalar(
        "SELECT state FROM github_check_projection_outbox WHERE subject_id = $1",
    )
    .bind(target.subject_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(state, "delivered");
    Ok(())
}

async fn drive_in_progress_and_terminal(
    database: &TestDatabase,
    fixture: &Fixture,
    target: &GithubCheckSubjectTarget,
) -> TestResult {
    let started_at = UnixMillis::new(database_now_ms(database).await?);
    database
        .store()
        .start_github_check_projection(StartGithubCheckProjection::new(target.clone(), started_at)?)
        .await?;
    let running = claim_projection(database, fixture)
        .await?
        .expect("in-progress publication");
    assert_eq!(running.action(), GithubCheckProjectionAction::Publish);
    database
        .store()
        .complete_github_check_projection(CompleteGithubCheckProjection::new(
            running.claim(),
            GithubCheckDesiredProjection::InProgress,
            live_observation(&running),
        )?)
        .await?;

    let terminal_at = UnixMillis::new(database_now_ms(database).await?);
    let terminal = database
        .store()
        .terminalize_github_check(TerminalizeGithubCheck::new(
            target.clone(),
            GithubCheckTerminalCause::ProviderUnknown,
            terminal_at,
        )?)
        .await?;
    assert_eq!(
        terminal.desired(),
        GithubCheckDesiredProjection::terminal(GithubCheckTerminalCause::ProviderUnknown)
    );
    let terminal_claim = claim_projection(database, fixture)
        .await?
        .expect("terminal publication");
    database
        .store()
        .complete_github_check_projection(CompleteGithubCheckProjection::new(
            terminal_claim.claim(),
            terminal.desired(),
            live_observation(&terminal_claim),
        )?)
        .await?;
    let row: (String, String, String) = sqlx::query_as(
        r"
        SELECT outbox.state, outbox.provider_state, outbox.provider_conclusion
        FROM github_check_projection_outbox AS outbox
        WHERE outbox.subject_id = $1
        ",
    )
    .bind(target.subject_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        row,
        (
            "delivered".into(),
            "completed".into(),
            "action_required".into(),
        )
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn ambiguous_create_is_durably_blocked_without_external_identity() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let receipt = database
            .store()
            .register_github_check_subject(registration(
                &fixture,
                ".github/workflows/ambiguous.yml",
                "Automata / Ambiguous",
                400,
            ))
            .await?;
        let ensure = claim_projection(&database, &fixture)
            .await?
            .expect("suite claim");
        database
            .store()
            .bind_github_check_suite(BindGithubCheckSuite::new(
                ensure.claim(),
                GithubCheckSuiteId::new(601)?,
                live_observation(&ensure),
            )?)
            .await?;
        let prepare = claim_projection(&database, &fixture)
            .await?
            .expect("create preparation");
        let create_fence = database
            .store()
            .begin_github_check_run_create(BeginGithubCheckRunCreate::new(
                &prepare,
                live_observation(&prepare),
                UnixMillis::new(prepare.expires_at().get() + 10),
            )?)
            .await?;
        assert!(
            claim_projection(&database, &fixture).await?.is_none(),
            "reconciliation must remain ineligible before its database horizon"
        );
        wait_until_database(&database, create_fence.reconcile_not_before()).await?;
        let reconcile = claim_projection(&database, &fixture)
            .await?
            .expect("reconciliation claim");
        database
            .store()
            .resolve_github_check_run_create(ResolveGithubCheckRunCreate::ambiguous(
                reconcile.claim(),
                live_observation(&reconcile),
            )?)
            .await?;
        let row: (String, Option<i64>, Option<i64>, String) = sqlx::query_as(
            r"
            SELECT state, external_run_id, projected_revision, blocked_reason
            FROM github_check_projection_outbox WHERE subject_id = $1
            ",
        )
        .bind(receipt.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(row.0, "blocked");
        assert_eq!(row.1, None);
        assert_eq!(row.2, Some(0));
        assert_eq!(row.3, "ambiguous_create");
        assert!(claim_projection(&database, &fixture).await?.is_none());
        Ok(())
    })
    .await
}

async fn seed_indeterminate_create(
    database: &TestDatabase,
    fixture: &Fixture,
    key: &str,
    name: &str,
    base: i64,
    suite_value: u64,
) -> TestResult<(
    GithubCheckSubjectReceipt,
    GithubCheckRunCreateFence,
    GithubCheckSuiteId,
)> {
    let receipt = database
        .store()
        .register_github_check_subject(registration(fixture, key, name, base))
        .await?;
    let ensure = claim_projection(database, fixture)
        .await?
        .expect("suite claim");
    let suite = GithubCheckSuiteId::new(suite_value)?;
    database
        .store()
        .bind_github_check_suite(BindGithubCheckSuite::new(
            ensure.claim(),
            suite,
            live_observation(&ensure),
        )?)
        .await?;
    let prepare = claim_projection(database, fixture)
        .await?
        .expect("create preparation");
    let fence = database
        .store()
        .begin_github_check_run_create(BeginGithubCheckRunCreate::new(
            &prepare,
            live_observation(&prepare),
            UnixMillis::new(prepare.expires_at().get() + 10),
        )?)
        .await?;
    Ok((receipt, fence, suite))
}

async fn assert_missing_create_schedule(
    database: &TestDatabase,
    subject_id: automata_ci_store::GithubCheckSubjectId,
    fence: GithubCheckRunCreateFence,
    missing: ResolveGithubCheckRunCreate,
) -> TestResult {
    let row: (String, i64, i64, i64, i64, Option<String>) = sqlx::query_as(
        r"
        SELECT state, create_started_at_ms, create_issue_expires_at_ms,
               reconcile_not_before_ms, next_reconcile_at_ms, blocked_reason
        FROM github_check_projection_outbox WHERE subject_id = $1
        ",
    )
    .bind(subject_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(row.0, "create_indeterminate");
    assert_eq!(row.1, fence.started_at().get());
    assert_eq!(row.2, fence.issue_expires_at().get());
    assert_eq!(row.3, fence.reconcile_not_before().get());
    assert_eq!(row.4, missing.retry_at().expect("missing retry").get());
    assert_eq!(row.5, None);
    let mutate_horizon = sqlx::query(
        r"
        UPDATE github_check_projection_outbox
        SET reconcile_not_before_ms = $2
        WHERE subject_id = $1
        ",
    )
    .bind(subject_id.as_uuid())
    .bind(fence.reconcile_not_before().get() - 1)
    .execute(database.pool())
    .await
    .expect_err("original reconciliation horizon is immutable");
    assert_constraint(
        &mutate_horizon,
        "github_check_projection_create_evidence_immutable",
    );
    let mutate_next = sqlx::query(
        r"
        UPDATE github_check_projection_outbox
        SET next_reconcile_at_ms = $2
        WHERE subject_id = $1
        ",
    )
    .bind(subject_id.as_uuid())
    .bind(missing.retry_at().expect("missing retry").get() + 1)
    .execute(database.pool())
    .await
    .expect_err("next reconciliation requires exact missing evidence");
    assert_constraint(&mutate_next, "github_check_projection_next_reconcile_exact");
    Ok(())
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn credential_rejection_blocks_only_the_exact_live_claim_without_losing_evidence()
-> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let (receipt, create_fence, suite) = seed_indeterminate_create(
            &database,
            &fixture,
            ".github/workflows/credential-rejection.yml",
            "Automata / Credential Rejection",
            500,
            801,
        )
        .await?;
        wait_until_database(&database, create_fence.reconcile_not_before()).await?;
        let claimed = claim_projection(&database, &fixture)
            .await?
            .expect("reconciliation claim");
        assert_eq!(
            claimed.action(),
            GithubCheckProjectionAction::ReconcileRunCreate
        );

        let before = github_check_outbox_snapshot(&database, receipt.subject_id()).await?;
        let wrong_owner = GithubCheckProjectionClaimFence::from_durable_parts(
            receipt.subject_id(),
            worker(),
            claimed.claim().fence(),
        )?;
        let wrong_fence = GithubCheckProjectionClaimFence::from_durable_parts(
            receipt.subject_id(),
            claimed.claim().owner(),
            claimed.claim().fence() + 1,
        )?;
        for request in [
            BlockGithubCheckProjectionForCredentialRejection::new(
                wrong_owner,
                live_observation(&claimed),
            )?,
            BlockGithubCheckProjectionForCredentialRejection::new(
                wrong_fence,
                live_observation(&claimed),
            )?,
            BlockGithubCheckProjectionForCredentialRejection::new(
                claimed.claim(),
                claimed.expires_at(),
            )?,
        ] {
            assert_credential_block_rejected_without_mutation(
                &database,
                receipt.subject_id(),
                request,
                &before,
            )
            .await?;
        }

        let blocked_at = live_observation(&claimed);
        assert_eq!(
            database
                .store()
                .block_github_check_projection_for_credential_rejection(
                    BlockGithubCheckProjectionForCredentialRejection::new(
                        claimed.claim(),
                        blocked_at,
                    )?,
                )
                .await?,
            receipt
        );
        assert_credential_rejection_blocked_state(
            &database,
            &fixture,
            &receipt,
            create_fence,
            suite,
            blocked_at,
        )
        .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn missing_create_retries_only_reconciliation_until_exact_bind() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let (receipt, fence, suite) = seed_indeterminate_create(
            &database,
            &fixture,
            ".github/workflows/missing.yml",
            "Automata / Missing",
            600,
            701,
        )
        .await?;
        wait_until_database(&database, fence.reconcile_not_before()).await?;
        let reconcile = claim_projection(&database, &fixture)
            .await?
            .expect("first reconciliation claim");
        assert_eq!(
            reconcile.action(),
            GithubCheckProjectionAction::ReconcileRunCreate
        );
        let observed_at = live_observation(&reconcile);
        let missing = ResolveGithubCheckRunCreate::missing(
            reconcile.claim(),
            observed_at,
            // Preserve enough live database time for exact replay and the
            // immutable schedule checks before proving retry ineligibility.
            UnixMillis::new(observed_at.get() + 5_000),
        )?;
        assert_eq!(
            database
                .store()
                .resolve_github_check_run_create(missing)
                .await?,
            receipt
        );
        assert_eq!(
            database
                .store()
                .resolve_github_check_run_create(missing)
                .await?,
            receipt
        );
        assert_missing_create_schedule(&database, receipt.subject_id(), fence, missing).await?;
        assert!(
            claim_projection(&database, &fixture).await?.is_none(),
            "missing reconciliation must retain its database retry horizon"
        );
        wait_until_database(&database, missing.retry_at().expect("missing retry")).await?;
        let visible = claim_projection(&database, &fixture)
            .await?
            .expect("reconcile-only retry claim");
        assert_eq!(
            visible.action(),
            GithubCheckProjectionAction::ReconcileRunCreate
        );
        database
            .store()
            .bind_github_check_run(BindGithubCheckRun::new(
                GithubCheckRunBindingFence::Reconciliation(visible.claim()),
                suite,
                GithubCheckRunId::new(801)?,
                live_observation(&visible),
            )?)
            .await?;
        let bound: (String, Option<i64>, Option<i64>) = sqlx::query_as(
            r"
            SELECT state, external_run_id, next_reconcile_at_ms
            FROM github_check_projection_outbox WHERE subject_id = $1
            ",
        )
        .bind(receipt.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(bound, ("delivered".into(), Some(801), None));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn proven_unissued_release_reopens_prepare_under_the_exact_fence_only() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        const RETRY_HORIZON_MILLIS: i64 = 1_000;

        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let (receipt, fence, _) = seed_indeterminate_create(
            &database,
            &fixture,
            ".github/workflows/unissued.yml",
            "Automata / Unissued",
            800,
            901,
        )
        .await?;
        let released_at = UnixMillis::new(database_now_ms(&database).await?);
        let retry_at = UnixMillis::new(released_at.get() + RETRY_HORIZON_MILLIS);
        let release = ReleaseUnissuedGithubCheckRunCreate::new(fence, released_at, retry_at)?;
        assert_eq!(
            database
                .store()
                .release_unissued_github_check_run_create(release)
                .await?,
            receipt
        );
        assert_eq!(
            database
                .store()
                .release_unissued_github_check_run_create(release)
                .await?,
            receipt
        );
        let retry: (String, Option<i64>, Option<String>) = sqlx::query_as(
            r"
            SELECT state, next_attempt_at_ms, last_failure_kind
            FROM github_check_projection_outbox WHERE subject_id = $1
            ",
        )
        .bind(receipt.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            retry,
            (
                "retry".into(),
                Some(retry_at.get()),
                Some("create_not_issued".into())
            )
        );
        let cleared: (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
            r"
            SELECT create_started_at_ms, reconcile_not_before_ms, next_reconcile_at_ms
            FROM github_check_projection_outbox WHERE subject_id = $1
            ",
        )
        .bind(receipt.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(cleared, (None, None, None));
        assert!(
            claim_projection(&database, &fixture).await?.is_none(),
            "released create must retain its database retry horizon"
        );
        wait_until_database(&database, retry_at).await?;
        let next = claim_projection(&database, &fixture)
            .await?
            .expect("released create is retryable");
        assert_eq!(next.action(), GithubCheckProjectionAction::PrepareRunCreate);
        assert!(matches!(
            database
                .store()
                .release_unissued_github_check_run_create(release)
                .await,
            Err(GithubCheckStoreError::ClaimRejected)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn missing_reconciliation_hits_explicit_attempt_limit_without_prepare_authority() -> TestResult
{
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let (receipt, fence, _) = seed_indeterminate_create(
            &database,
            &fixture,
            ".github/workflows/missing-limit.yml",
            "Automata / Missing Limit",
            1_000,
            1_001,
        )
        .await?;
        let mut eligible_at = fence.reconcile_not_before();
        for expected_attempt in 3_u16..=64 {
            wait_until_database(&database, eligible_at).await?;
            let reconcile = claim_projection(&database, &fixture)
                .await?
                .expect("bounded reconciliation claim");
            assert_eq!(reconcile.attempts(), expected_attempt);
            assert_eq!(
                reconcile.action(),
                GithubCheckProjectionAction::ReconcileRunCreate
            );
            let observed_at = live_observation(&reconcile);
            let retry_at = UnixMillis::new(observed_at.get() + 1);
            let resolution =
                ResolveGithubCheckRunCreate::missing(reconcile.claim(), observed_at, retry_at)?;
            database
                .store()
                .resolve_github_check_run_create(resolution)
                .await?;
            if expected_attempt == 64 {
                database
                    .store()
                    .resolve_github_check_run_create(resolution)
                    .await?;
            }
            eligible_at = retry_at;
        }
        let row: (String, String, i16, Option<i64>) = sqlx::query_as(
            r"
            SELECT state, blocked_reason, attempt_count, external_run_id
            FROM github_check_projection_outbox WHERE subject_id = $1
            ",
        )
        .bind(receipt.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(row, ("blocked".into(), "attempt_limit".into(), 64, None));
        assert!(claim_projection(&database, &fixture).await?.is_none());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn projection_claims_use_database_time_for_fast_slow_and_forward_callers() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        database
            .store()
            .register_github_check_subject(registration(
                &fixture,
                ".github/workflows/database-clock.yml",
                "Automata / Database Clock",
                100,
            ))
            .await?;

        let before_first = database_now_ms(&database).await?;
        let fast_caller = before_first + 30_000;
        let first = database
            .store()
            .claim_github_check_projection(claim_request_at(&fixture, fast_caller, 321))
            .await?
            .expect("bounded fast caller is admitted");
        let after_first = database_now_ms(&database).await?;
        assert!((before_first..=after_first).contains(&first.claimed_at().get()));
        assert_ne!(first.claimed_at().get(), fast_caller);
        assert_eq!(first.expires_at().get() - first.claimed_at().get(), 321);

        let forward_caller = database_now_ms(&database).await? + 59_000;
        assert!(
            database
                .store()
                .claim_github_check_projection(claim_request_at(&fixture, forward_caller, 321,))
                .await?
                .is_none(),
            "a forward caller clock must not take over a database-live claim"
        );

        wait_until_database(&database, first.expires_at()).await?;
        let before_takeover = database_now_ms(&database).await?;
        let slow_caller = before_takeover - 30_000;
        let takeover = database
            .store()
            .claim_github_check_projection(claim_request_at(&fixture, slow_caller, 321))
            .await?
            .expect("bounded slow caller observes database-due takeover");
        let after_takeover = database_now_ms(&database).await?;
        assert_eq!(takeover.claim().fence(), first.claim().fence() + 1);
        assert!((before_takeover..=after_takeover).contains(&takeover.claimed_at().get()));
        assert_ne!(takeover.claimed_at().get(), slow_caller);
        assert_eq!(
            takeover.expires_at().get() - takeover.claimed_at().get(),
            321
        );

        for skew in [-120_000, 120_000] {
            let observed_at = database_now_ms(&database).await? + skew;
            assert!(matches!(
                database
                    .store()
                    .claim_github_check_projection(claim_request_at(&fixture, observed_at, 321,))
                    .await,
                Err(GithubCheckStoreError::ClaimRejected)
            ));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn projection_claim_transaction_is_explicitly_read_committed() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        database
            .store()
            .register_github_check_subject(registration(
                &fixture,
                ".github/workflows/read-committed.yml",
                "Automata / Read Committed",
                100,
            ))
            .await?;
        sqlx::query(
            r"
            CREATE FUNCTION checks_test_require_read_committed() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF current_setting('transaction_isolation') <> 'read committed' THEN
                    RAISE EXCEPTION 'Checks claim transaction is not READ COMMITTED';
                END IF;
                RETURN NEW;
            END;
            $$
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            CREATE TRIGGER checks_test_require_read_committed
            BEFORE UPDATE ON github_check_projection_outbox
            FOR EACH ROW WHEN (NEW.state = 'claimed')
            EXECUTE FUNCTION checks_test_require_read_committed()
            ",
        )
        .execute(database.pool())
        .await?;

        assert!(claim_projection(&database, &fixture).await?.is_some());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn delayed_exhaustion_lock_revalidates_the_caller_clock_before_claiming() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let receipt = database
            .store()
            .register_github_check_subject(registration(
                &fixture,
                ".github/workflows/delayed-lock.yml",
                "Automata / Delayed Lock",
                100,
            ))
            .await?;
        sqlx::query("ALTER TABLE github_check_projection_outbox DISABLE TRIGGER USER")
            .execute(database.pool())
            .await?;
        sqlx::query(
            r"
            UPDATE github_check_projection_outbox
            SET attempted_revision = 1, attempt_count = 64
            WHERE subject_id = $1
            ",
        )
        .bind(receipt.subject_id().as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query("ALTER TABLE github_check_projection_outbox ENABLE TRIGGER USER")
            .execute(database.pool())
            .await?;

        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query(
            "SELECT subject_id FROM github_check_projection_outbox WHERE subject_id = $1 FOR UPDATE",
        )
        .bind(receipt.subject_id().as_uuid())
        .fetch_one(&mut *blocker)
        .await?;

        let observed_at = database_now_ms(&database).await? - 59_800;
        let request = claim_request_at(&fixture, observed_at, CLAIM_MILLIS);
        let store = database.store().clone();
        let waiting_claim =
            tokio::spawn(async move { store.claim_github_check_projection(request).await });
        let mut observed_waiter = false;
        for _ in 0..100 {
            observed_waiter = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1 FROM pg_stat_activity AS activity
                    WHERE $1 = ANY(pg_blocking_pids(activity.pid))
                      AND activity.query LIKE '%UPDATE github_check_projection_outbox AS outbox%'
                )
                ",
            )
            .bind(blocker_pid)
            .fetch_one(database.pool())
            .await?;
            if observed_waiter {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(observed_waiter, "Checks claim did not wait on the exhausted row");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        blocker.commit().await?;

        let delayed_result = waiting_claim.await?;
        assert!(matches!(
            delayed_result,
            Err(GithubCheckStoreError::ClaimRejected)
        ));
        let state: (String, i16, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT state, attempt_count, claim_owner_id
            FROM github_check_projection_outbox WHERE subject_id = $1
            ",
        )
        .bind(receipt.subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(state, ("pending".into(), 64, None));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn projection_claims_are_single_winner_fenced_and_schema_rejects_positive_unknowns()
-> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_checks_migrations(&database).await?;
        let fixture = seed_fixture(&database).await?;
        let receipt = database
            .store()
            .register_github_check_subject(registration(
                &fixture,
                ".github/workflows/fenced.yml",
                "Automata / Fenced",
                100,
            ))
            .await?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let observed_at = database_now_ms(&database).await?;
        let left_request = claim_request_at(&fixture, observed_at, CLAIM_MILLIS);
        let right_request = claim_request_at(&fixture, observed_at, CLAIM_MILLIS);
        let (left, right) = tokio::join!(
            left_store.claim_github_check_projection(left_request),
            right_store.claim_github_check_projection(right_request),
        );
        let mut winners = [left?, right?].into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(winners.len(), 1);
        let stale = winners.pop().expect("single claim winner");
        assert_eq!(stale.claim().fence(), 1);
        assert!(claim_projection(&database, &fixture).await?.is_none());
        wait_until_database(&database, stale.expires_at()).await?;
        let current = claim_projection(&database, &fixture)
            .await?
            .expect("expired claim is reclaimed");
        assert_eq!(current.claim().fence(), 2);
        assert!(matches!(
            database
                .store()
                .bind_github_check_suite(BindGithubCheckSuite::new(
                    stale.claim(),
                    GithubCheckSuiteId::new(701)?,
                    live_observation(&current),
                )?)
                .await,
            Err(GithubCheckStoreError::ClaimRejected)
        ));
        database
            .store()
            .bind_github_check_suite(BindGithubCheckSuite::new(
                current.claim(),
                GithubCheckSuiteId::new(701)?,
                live_observation(&current),
            )?)
            .await?;
        assert!(matches!(
            database
                .store()
                .bind_github_check_suite(BindGithubCheckSuite::new(
                    current.claim(),
                    GithubCheckSuiteId::new(702)?,
                    live_observation(&current),
                )?)
                .await,
            Err(GithubCheckStoreError::ExternalIdentityConflict)
        ));

        let positive_unknown = sqlx::query(
            r"
            UPDATE github_check_subjects
            SET desired_state = 'completed', desired_conclusion = 'success',
                terminal_cause = 'provider_unknown', desired_revision = 2,
                desired_updated_at_ms = 200
            WHERE id = $1
            ",
        )
        .bind(receipt.subject_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("provider unknown cannot become success");
        assert_constraint(&positive_unknown, "github_check_subjects_terminal_mapping");
        let deletion = sqlx::query("DELETE FROM github_check_subjects WHERE id = $1")
            .bind(receipt.subject_id().as_uuid())
            .execute(database.pool())
            .await
            .expect_err("durable subject deletion must fail");
        assert_constraint(&deletion, "github_check_evidence_removal_forbidden");
        Ok(())
    })
    .await
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some(expected)
    );
}
