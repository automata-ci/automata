#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use automata_ci_core::{JobAuthorityProfile, Sha256Digest, UnixMillis};
use automata_ci_store::{
    ClaimGithubServerServiceMint, EnsureGithubServerServiceAuthority, GithubCheckName,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceAuthoritySelector,
    GithubServerServiceGeneration, GithubServerServiceIssuanceState, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubServerServiceWorkerId,
    ProviderConnectionId, ProviderInstallationId, ProviderRepositoryId,
    ProviderRepositoryVisibility, ReconcileExpiredGithubServerServiceMint, TenantScope,
};
use sqlx::{AssertSqlSafe, migrate::Migrate as _};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_unmigrated_database};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const INSTALLATION_ID: u64 = 101;
const GITHUB_REPOSITORY_ID: u64 = 202;
const APP_ID: u64 = 303;
const APP_CONFIGURATION_REVISION: u64 = 1;
const COMPATIBLE_CHECKS_V1_FINGERPRINT: [u8; 32] = [
    0x86, 0xdb, 0x54, 0xf0, 0x98, 0xad, 0xc5, 0x12, 0x19, 0xd1, 0x76, 0x55, 0x5d, 0x5f, 0x7b, 0x54,
    0x61, 0xa4, 0xc4, 0x5d, 0xdd, 0x06, 0x25, 0x39, 0x38, 0x46, 0xb1, 0xb3, 0xa5, 0xae, 0x65, 0x43,
];
const COMPATIBLE_PRIVATE_V1_FINGERPRINT: [u8; 32] = [
    0x87, 0x8f, 0x4b, 0xd0, 0x1b, 0xfe, 0x4b, 0x04, 0xe8, 0x4d, 0x9b, 0x9e, 0xee, 0x32, 0x66, 0x7d,
    0x31, 0xd5, 0x5f, 0xee, 0xbe, 0x78, 0xa7, 0xb2, 0xf5, 0x9e, 0xd7, 0x15, 0xb1, 0x14, 0x5b, 0x32,
];

#[derive(Debug)]
struct ManifestFixture {
    connection_id: ProviderConnectionId,
    current: GithubProviderManifest,
}

#[derive(Debug)]
struct PrivateRouteFixture {
    current_checks: GithubServerServiceAuthorityIdentity,
    current_private: GithubServerServiceAuthorityIdentity,
    compatible_checks_v1_historical: GithubServerServiceAuthorityIdentity,
    compatible_private_v1_historical: GithubServerServiceAuthorityIdentity,
    unknown_checks_historical: GithubServerServiceAuthorityIdentity,
    swapped_scope_checks_historical: GithubServerServiceAuthorityIdentity,
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_preserves_scope_bound_v1_history_and_retires_safe_unknown_and_swapped_history()
-> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_through_0052(&database).await?;
        install_database_test_clock(&database, 100).await?;
        let manifest = bootstrap_private_manifest_history(&database).await?;
        let authorities = seed_private_routes(&database, &manifest).await?;
        reject_one_unissued_generation(&database, &authorities.unknown_checks_historical, 600)
            .await?;
        reject_one_unissued_generation(
            &database,
            &authorities.swapped_scope_checks_historical,
            700,
        )
        .await?;

        let manifest_before = manifest_snapshot(&database, manifest.connection_id).await?;
        let current_checks_before =
            authority_snapshot(&database, &authorities.current_checks).await?;
        let current_private_before =
            authority_snapshot(&database, &authorities.current_private).await?;
        let compatible_checks_before =
            authority_snapshot(&database, &authorities.compatible_checks_v1_historical).await?;
        let compatible_private_before =
            authority_snapshot(&database, &authorities.compatible_private_v1_historical).await?;
        let unknown_identity_before =
            authority_identity_snapshot(&database, &authorities.unknown_checks_historical).await?;
        let unknown_issuance_before =
            issuance_snapshot(&database, &authorities.unknown_checks_historical).await?;
        let swapped_identity_before =
            authority_identity_snapshot(&database, &authorities.swapped_scope_checks_historical)
                .await?;
        let swapped_issuance_before =
            issuance_snapshot(&database, &authorities.swapped_scope_checks_historical).await?;

        set_database_test_clock(&database, 100_000).await?;
        apply_0053(&database).await?;

        assert_eq!(
            manifest_snapshot(&database, manifest.connection_id).await?,
            manifest_before
        );
        assert_eq!(
            authority_snapshot(&database, &authorities.current_checks).await?,
            current_checks_before
        );
        assert_eq!(
            authority_snapshot(&database, &authorities.current_private).await?,
            current_private_before
        );
        assert_eq!(
            authority_snapshot(&database, &authorities.compatible_checks_v1_historical).await?,
            compatible_checks_before
        );
        assert_eq!(
            authority_snapshot(&database, &authorities.compatible_private_v1_historical).await?,
            compatible_private_before
        );
        assert_eq!(
            authority_identity_snapshot(&database, &authorities.unknown_checks_historical).await?,
            unknown_identity_before
        );
        assert_eq!(
            issuance_snapshot(&database, &authorities.unknown_checks_historical).await?,
            unknown_issuance_before,
            "migration must not rewrite unknown-route issuance history"
        );
        assert_eq!(
            authority_identity_snapshot(&database, &authorities.swapped_scope_checks_historical,)
                .await?,
            swapped_identity_before
        );
        assert_eq!(
            issuance_snapshot(&database, &authorities.swapped_scope_checks_historical).await?,
            swapped_issuance_before,
            "migration must not rewrite swapped-scope issuance history"
        );
        assert_authority_state(
            &database,
            &authorities.unknown_checks_historical,
            "retired",
            Some(100_000),
        )
        .await?;
        assert_authority_state(
            &database,
            &authorities.swapped_scope_checks_historical,
            "retired",
            Some(100_000),
        )
        .await?;
        assert!(migration_0053_applied(&database).await?);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_retires_obsolete_private_route_after_public_transition() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_through_0052(&database).await?;
        install_database_test_clock(&database, 100).await?;
        let manifest = bootstrap_public_successor_of_private(&database).await?;
        let current_checks = ensure_authority(
            &database,
            authority(
                &manifest.current,
                GithubServerServiceScope::ChecksWrite,
                2,
                [0x51; 32],
            )?,
            300,
        )
        .await?;
        let obsolete_private = ensure_authority(
            &database,
            authority(
                &manifest.current,
                GithubServerServiceScope::PrivateRepositorySourceRead,
                1,
                COMPATIBLE_PRIVATE_V1_FINGERPRINT,
            )?,
            301,
        )
        .await?;
        assert_eq!(
            obsolete_private.configuration_fingerprint(),
            Sha256Digest::from_bytes(COMPATIBLE_PRIVATE_V1_FINGERPRINT)
        );
        let manifest_before = manifest_snapshot(&database, manifest.connection_id).await?;
        let current_before = authority_snapshot(&database, &current_checks).await?;
        let obsolete_identity_before =
            authority_identity_snapshot(&database, &obsolete_private).await?;

        set_database_test_clock(&database, 1_000).await?;
        apply_0053(&database).await?;

        assert_eq!(
            manifest_snapshot(&database, manifest.connection_id).await?,
            manifest_before
        );
        assert_eq!(
            authority_snapshot(&database, &current_checks).await?,
            current_before
        );
        assert_eq!(
            authority_identity_snapshot(&database, &obsolete_private).await?,
            obsolete_identity_before
        );
        assert_authority_state(&database, &obsolete_private, "retired", Some(1_000)).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_rejects_a_missing_current_route_without_partial_ddl() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_through_0052(&database).await?;
        install_database_test_clock(&database, 100).await?;
        let manifest = bootstrap_public_manifest(&database).await?;
        let manifest_before = manifest_snapshot(&database, manifest.connection_id).await?;

        set_database_test_clock(&database, 1_000).await?;
        let error = apply_0053(&database)
            .await
            .expect_err("a current manifest without its exact active route must fail");
        assert_migration_constraint(error, "github_server_service_current_manifest_route_exact");
        assert_eq!(
            manifest_snapshot(&database, manifest.connection_id).await?,
            manifest_before
        );
        assert_failed_migration_rolled_back(&database).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn migration_rejects_nonterminal_incompatible_history_atomically() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        apply_through_0052(&database).await?;
        install_database_test_clock(&database, 100).await?;
        let manifest = bootstrap_public_manifest(&database).await?;
        let current = ensure_authority(
            &database,
            authority(
                &manifest.current,
                GithubServerServiceScope::ChecksWrite,
                1,
                [0x71; 32],
            )?,
            200,
        )
        .await?;
        let incompatible = ensure_authority(
            &database,
            authority(
                &manifest.current,
                GithubServerServiceScope::ChecksWrite,
                2,
                [0x72; 32],
            )?,
            201,
        )
        .await?;
        claim_one_generation(&database, &incompatible, 300).await?;
        let manifest_before = manifest_snapshot(&database, manifest.connection_id).await?;
        let current_before = authority_snapshot(&database, &current).await?;
        let incompatible_before = authority_snapshot(&database, &incompatible).await?;
        let issuance_before = issuance_snapshot(&database, &incompatible).await?;

        set_database_test_clock(&database, 1_000).await?;
        let error = apply_0053(&database)
            .await
            .expect_err("nonterminal incompatible issuance must block migration");
        assert_migration_constraint(
            error,
            "github_server_service_historical_route_retirement_safe",
        );
        assert_eq!(
            manifest_snapshot(&database, manifest.connection_id).await?,
            manifest_before
        );
        assert_eq!(
            authority_snapshot(&database, &current).await?,
            current_before
        );
        assert_eq!(
            authority_snapshot(&database, &incompatible).await?,
            incompatible_before
        );
        assert_eq!(
            issuance_snapshot(&database, &incompatible).await?,
            issuance_before
        );
        assert_failed_migration_rolled_back(&database).await?;
        Ok(())
    })
    .await
}

async fn apply_through_0052(database: &TestDatabase) -> TestResult {
    let mut connection = database.pool().acquire().await?;
    connection
        .ensure_migrations_table(MIGRATOR.table_name.as_ref())
        .await?;
    for migration in MIGRATOR.iter().filter(|migration| migration.version <= 52) {
        connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await?;
    }
    Ok(())
}

async fn apply_0053(database: &TestDatabase) -> Result<(), sqlx::migrate::MigrateError> {
    let mut connection = database
        .pool()
        .acquire()
        .await
        .map_err(sqlx::migrate::MigrateError::Execute)?;
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 53)
        .expect("credential-rejection migration");
    connection
        .apply(MIGRATOR.table_name.as_ref(), migration)
        .await
        .map(|_| ())
}

async fn install_database_test_clock(database: &TestDatabase, now_ms: i64) -> TestResult {
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(database.pool())
        .await?;
    if !schema
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("test schema contains a non-identifier byte".into());
    }
    let schema = format!("\"{schema}\"");
    sqlx::query(AssertSqlSafe(format!(
        "CREATE TABLE {schema}.github_check_migration_test_clock (\
         singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), \
         now_ms BIGINT NOT NULL CHECK (now_ms >= 0))"
    )))
    .execute(database.pool())
    .await?;
    sqlx::query(AssertSqlSafe(format!(
        "INSERT INTO {schema}.github_check_migration_test_clock (singleton, now_ms) \
         VALUES (TRUE, $1)"
    )))
    .bind(now_ms)
    .execute(database.pool())
    .await?;
    sqlx::query(AssertSqlSafe(format!(
        "CREATE FUNCTION {schema}.clock_timestamp() RETURNS TIMESTAMPTZ \
         LANGUAGE SQL VOLATILE AS $clock$ \
         SELECT TIMESTAMPTZ 'epoch' + now_ms * INTERVAL '1 millisecond' \
         FROM {schema}.github_check_migration_test_clock WHERE singleton \
         $clock$"
    )))
    .execute(database.pool())
    .await?;
    set_database_test_clock(database, now_ms).await
}

async fn set_database_test_clock(database: &TestDatabase, now_ms: i64) -> TestResult {
    let updated =
        sqlx::query("UPDATE github_check_migration_test_clock SET now_ms = $1 WHERE singleton")
            .bind(now_ms)
            .execute(database.pool())
            .await?;
    assert_eq!(updated.rows_affected(), 1);
    let observed: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    assert_eq!(observed, now_ms);
    Ok(())
}

async fn bootstrap_private_manifest_history(
    database: &TestDatabase,
) -> TestResult<ManifestFixture> {
    let tenant = tenant("private-history")?;
    let connection_id = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
    let mut current = manifest(
        tenant.clone(),
        connection_id,
        ProviderRepositoryVisibility::Private,
        1,
        1,
    )?;
    bootstrap_manifest(database, current.clone(), 100).await?;
    current = manifest(
        tenant,
        connection_id,
        ProviderRepositoryVisibility::Private,
        2,
        2,
    )?;
    bootstrap_manifest(database, current.clone(), 200).await?;
    Ok(ManifestFixture {
        connection_id,
        current,
    })
}

async fn bootstrap_public_successor_of_private(
    database: &TestDatabase,
) -> TestResult<ManifestFixture> {
    let tenant = tenant("public-successor")?;
    let connection_id = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
    let private = manifest(
        tenant.clone(),
        connection_id,
        ProviderRepositoryVisibility::Private,
        1,
        1,
    )?;
    bootstrap_manifest(database, private, 100).await?;
    let current = manifest(
        tenant.clone(),
        connection_id,
        ProviderRepositoryVisibility::Public,
        2,
        2,
    )?;
    bootstrap_manifest(database, current.clone(), 200).await?;
    Ok(ManifestFixture {
        connection_id,
        current,
    })
}

async fn bootstrap_public_manifest(database: &TestDatabase) -> TestResult<ManifestFixture> {
    let tenant = tenant("public-current")?;
    let connection_id = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
    let current = manifest(
        tenant.clone(),
        connection_id,
        ProviderRepositoryVisibility::Public,
        1,
        1,
    )?;
    bootstrap_manifest(database, current.clone(), 100).await?;
    Ok(ManifestFixture {
        connection_id,
        current,
    })
}

async fn bootstrap_manifest(
    database: &TestDatabase,
    manifest: GithubProviderManifest,
    applied_at: i64,
) -> TestResult {
    set_database_test_clock(database, applied_at).await?;
    let receipt = database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                UnixMillis::new(applied_at),
            ),
        )
        .await?;
    assert_eq!(receipt.manifest().current().manifest(), &manifest);
    Ok(())
}

fn manifest(
    tenant: TenantScope,
    connection_id: ProviderConnectionId,
    visibility: ProviderRepositoryVisibility,
    manifest_revision: u64,
    policy_revision: u64,
) -> TestResult<GithubProviderManifest> {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(policy_revision);
    Ok(GithubProviderManifest::new(
        tenant,
        connection_id,
        ProviderInstallationId::new(INSTALLATION_ID)?,
        ProviderRepositoryId::new(GITHUB_REPOSITORY_ID)?,
        GithubRepositoryName::new("automata-ci/automata")?,
        visibility,
        GithubServerServiceAppId::new(APP_ID)?,
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766")?,
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x11; 32]),
        GithubServerServiceRevision::new(APP_CONFIGURATION_REVISION)?,
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes(
            [0x21; 32],
        ))?,
        GithubServerServiceRevision::new(1)?,
        GithubServerServiceRevision::new(policy_revision)?,
        JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI")?,
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(manifest_revision)?,
    ))
}

fn tenant(suffix: &str) -> TestResult<TenantScope> {
    Ok(TenantScope::from_authenticated_tenant_id(format!(
        "check-migration-{suffix}-{}",
        Uuid::new_v4().simple()
    ))?)
}

async fn seed_private_routes(
    database: &TestDatabase,
    manifest: &ManifestFixture,
) -> TestResult<PrivateRouteFixture> {
    let current_checks = ensure_authority(
        database,
        authority(
            &manifest.current,
            GithubServerServiceScope::ChecksWrite,
            2,
            [0x31; 32],
        )?,
        300,
    )
    .await?;
    let current_private = ensure_authority(
        database,
        authority(
            &manifest.current,
            GithubServerServiceScope::PrivateRepositorySourceRead,
            2,
            [0x41; 32],
        )?,
        301,
    )
    .await?;
    let compatible_checks_v1_historical = ensure_authority(
        database,
        authority(
            &manifest.current,
            GithubServerServiceScope::ChecksWrite,
            1,
            COMPATIBLE_CHECKS_V1_FINGERPRINT,
        )?,
        302,
    )
    .await?;
    let compatible_private_v1_historical = ensure_authority(
        database,
        authority(
            &manifest.current,
            GithubServerServiceScope::PrivateRepositorySourceRead,
            1,
            COMPATIBLE_PRIVATE_V1_FINGERPRINT,
        )?,
        303,
    )
    .await?;
    let unknown_checks_historical = ensure_authority(
        database,
        authority(
            &manifest.current,
            GithubServerServiceScope::ChecksWrite,
            3,
            [0x32; 32],
        )?,
        304,
    )
    .await?;
    let swapped_scope_checks_historical = ensure_authority(
        database,
        authority(
            &manifest.current,
            GithubServerServiceScope::ChecksWrite,
            4,
            COMPATIBLE_PRIVATE_V1_FINGERPRINT,
        )?,
        305,
    )
    .await?;
    let fixture = PrivateRouteFixture {
        current_checks,
        current_private,
        compatible_checks_v1_historical,
        compatible_private_v1_historical,
        unknown_checks_historical,
        swapped_scope_checks_historical,
    };
    assert_private_route_fixture(&fixture);
    Ok(fixture)
}

fn assert_private_route_fixture(fixture: &PrivateRouteFixture) {
    assert_eq!(
        fixture
            .compatible_checks_v1_historical
            .configuration_fingerprint(),
        Sha256Digest::from_bytes(COMPATIBLE_CHECKS_V1_FINGERPRINT)
    );
    assert_eq!(
        fixture.compatible_checks_v1_historical.scope(),
        GithubServerServiceScope::ChecksWrite
    );
    assert_eq!(
        fixture
            .compatible_private_v1_historical
            .configuration_fingerprint(),
        Sha256Digest::from_bytes(COMPATIBLE_PRIVATE_V1_FINGERPRINT)
    );
    assert_eq!(
        fixture.compatible_private_v1_historical.scope(),
        GithubServerServiceScope::PrivateRepositorySourceRead
    );
    assert_ne!(
        fixture.current_checks.configuration_fingerprint(),
        fixture
            .compatible_checks_v1_historical
            .configuration_fingerprint()
    );
    assert_ne!(
        fixture.current_private.configuration_fingerprint(),
        fixture
            .compatible_private_v1_historical
            .configuration_fingerprint()
    );
    assert_ne!(
        fixture
            .unknown_checks_historical
            .configuration_fingerprint(),
        fixture.current_checks.configuration_fingerprint()
    );
    assert_ne!(
        fixture
            .unknown_checks_historical
            .configuration_fingerprint(),
        fixture
            .compatible_checks_v1_historical
            .configuration_fingerprint()
    );
    assert_ne!(
        fixture
            .unknown_checks_historical
            .configuration_fingerprint(),
        fixture
            .compatible_private_v1_historical
            .configuration_fingerprint()
    );
    assert_eq!(
        fixture.swapped_scope_checks_historical.scope(),
        GithubServerServiceScope::ChecksWrite
    );
    assert_eq!(
        fixture
            .swapped_scope_checks_historical
            .configuration_fingerprint(),
        fixture
            .compatible_private_v1_historical
            .configuration_fingerprint()
    );
}

fn authority(
    manifest: &GithubProviderManifest,
    scope: GithubServerServiceScope,
    policy_revision: u64,
    configuration_fingerprint: [u8; 32],
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    Ok(GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::new_v4())?,
        manifest.repository_id(),
        manifest.connection_id(),
        manifest.installation_id(),
        manifest.github_app_id(),
        manifest.github_repository_id(),
        manifest.github_repository_name().clone(),
        scope,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        GithubServerServiceRevision::new(policy_revision)?,
        Sha256Digest::from_bytes(configuration_fingerprint),
    )?)
}

async fn ensure_authority(
    database: &TestDatabase,
    identity: GithubServerServiceAuthorityIdentity,
    created_at: i64,
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    set_database_test_clock(database, created_at).await?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            identity.clone(),
            UnixMillis::new(created_at),
        )?)
        .await?;
    Ok(identity)
}

async fn claim_one_generation(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    requested_at: i64,
) -> TestResult<automata_ci_store::GithubServerServiceIssuanceKey> {
    set_database_test_clock(database, requested_at).await?;
    let claimed = database
        .store()
        .claim_github_server_service_mint(ClaimGithubServerServiceMint::new(
            GithubServerServiceAuthoritySelector::from_identity(identity),
            GithubServerServiceGeneration::new(1)?,
            GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
            UnixMillis::new(requested_at),
            UnixMillis::new(requested_at + 20),
            UnixMillis::new(requested_at + 10),
        )?)
        .await?;
    Ok(claimed.claim().key())
}

async fn reject_one_unissued_generation(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    requested_at: i64,
) -> TestResult {
    let key = claim_one_generation(database, identity, requested_at).await?;
    set_database_test_clock(database, requested_at + 10).await?;
    let receipt = database
        .store()
        .reconcile_expired_github_server_service_mint(ReconcileExpiredGithubServerServiceMint::new(
            GithubServerServiceAuthoritySelector::from_identity(identity),
            key,
            UnixMillis::new(requested_at + 10),
        )?)
        .await?;
    assert_eq!(receipt.state(), GithubServerServiceIssuanceState::Rejected);
    let terminal_and_custody_free: bool = sqlx::query_scalar(
        "SELECT state = 'rejected' AND envelope_schema IS NULL \
         FROM github_server_service_authority_issuances \
         WHERE authority_id = $1 AND generation = 1",
    )
    .bind(identity.authority_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert!(terminal_and_custody_free);
    Ok(())
}

async fn manifest_snapshot(
    database: &TestDatabase,
    connection_id: ProviderConnectionId,
) -> TestResult<String> {
    Ok(sqlx::query_scalar(
        r"
        SELECT jsonb_build_object(
            'current', (
                SELECT to_jsonb(current_manifest)
                FROM github_provider_manifest_current AS current_manifest
                WHERE current_manifest.provider_connection_id = $1
            ),
            'revisions', (
                SELECT jsonb_agg(to_jsonb(revision) ORDER BY revision.manifest_revision)
                FROM github_provider_manifest_revisions AS revision
                WHERE revision.provider_connection_id = $1
            )
        )::TEXT
        ",
    )
    .bind(connection_id.as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn authority_snapshot(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
) -> TestResult<String> {
    Ok(sqlx::query_scalar(
        "SELECT to_jsonb(authority)::TEXT FROM github_server_service_authorities AS authority \
         WHERE authority.id = $1",
    )
    .bind(identity.authority_id().as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn authority_identity_snapshot(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
) -> TestResult<String> {
    Ok(sqlx::query_scalar(
        r"
        SELECT to_jsonb(immutable_authority)::TEXT
        FROM (
            SELECT id, tenant_id, repository_id, provider_connection_id,
                   provider_installation_id, github_app_id, github_app_client_id,
                   github_app_jwt_issuer_kind, github_repository_id,
                   github_repository_name, service_scope, permission_policy,
                   policy_digest, policy_revision, app_key_spki_sha256,
                   app_configuration_revision, configuration_fingerprint,
                   identity_digest, created_at_ms
            FROM github_server_service_authorities
            WHERE id = $1
        ) AS immutable_authority
        ",
    )
    .bind(identity.authority_id().as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn issuance_snapshot(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
) -> TestResult<String> {
    Ok(sqlx::query_scalar(
        r"
        SELECT COALESCE(
            jsonb_agg(to_jsonb(issuance) ORDER BY issuance.generation),
            '[]'::JSONB
        )::TEXT
        FROM github_server_service_authority_issuances AS issuance
        WHERE issuance.authority_id = $1
        ",
    )
    .bind(identity.authority_id().as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn assert_authority_state(
    database: &TestDatabase,
    identity: &GithubServerServiceAuthorityIdentity,
    expected_state: &str,
    expected_retired_at: Option<i64>,
) -> TestResult {
    let state: (String, Option<i64>, i64) = sqlx::query_as(
        "SELECT state, retired_at_ms, state_updated_at_ms \
         FROM github_server_service_authorities WHERE id = $1",
    )
    .bind(identity.authority_id().as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(state.0, expected_state);
    assert_eq!(state.1, expected_retired_at);
    if let Some(retired_at) = expected_retired_at {
        assert_eq!(state.2, retired_at);
    }
    Ok(())
}

async fn migration_0053_applied(database: &TestDatabase) -> TestResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 53 AND success)",
    )
    .fetch_one(database.pool())
    .await?)
}

async fn assert_failed_migration_rolled_back(database: &TestDatabase) -> TestResult {
    assert!(!migration_0053_applied(database).await?);
    let function_exists: bool = sqlx::query_scalar(
        "SELECT to_regprocedure(\
         'automata_github_check_credential_rejection_guard()') IS NOT NULL",
    )
    .fetch_one(database.pool())
    .await?;
    assert!(
        !function_exists,
        "failed migration retained its trigger function"
    );
    let block_constraint: String = sqlx::query_scalar(
        r"
        SELECT pg_get_constraintdef(catalog_constraint.oid)
        FROM pg_constraint AS catalog_constraint
        WHERE catalog_constraint.conrelid = 'github_check_projection_outbox'::REGCLASS
          AND catalog_constraint.conname = 'github_check_projection_outbox_block_shape'
        ",
    )
    .fetch_one(database.pool())
    .await?;
    assert!(!block_constraint.contains("credential_rejected"));
    Ok(())
}

fn assert_migration_constraint(error: sqlx::migrate::MigrateError, expected: &str) {
    let database_error = match error {
        sqlx::migrate::MigrateError::ExecuteMigration(
            sqlx::Error::Database(database_error),
            53,
        )
        | sqlx::migrate::MigrateError::Execute(sqlx::Error::Database(database_error)) => {
            database_error
        }
        other => panic!("unexpected migration failure: {other:?}"),
    };
    assert_eq!(database_error.code().as_deref(), Some("23514"));
    assert_eq!(database_error.constraint(), Some(expected));
}
