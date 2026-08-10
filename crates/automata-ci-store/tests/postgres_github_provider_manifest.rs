#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_store::{
    BootstrapGithubProviderRepository, GithubCheckName, GithubProviderManifest,
    GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderManifestStoreError, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, GithubServerServiceRevision,
    ProviderConnectionId, ProviderInstallationId, ProviderRepositoryId,
    ProviderRepositoryVisibility, TenantScope, github_provider_repository_id,
};
use uuid::Uuid;

use common::{TestResult, run_with_database};

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn exact_bootstrap_creates_repository_and_replays_original_evidence() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("automata-ci");
        let connection = connection(0x100);
        let desired = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
        );
        let created = database
            .store()
            .bootstrap_github_provider_repository(request(desired.clone(), 100))
            .await?;
        assert!(!created.manifest().is_replay());
        assert_eq!(created.manifest().current().manifest(), &desired);
        assert_eq!(
            created.manifest().current().registered_at(),
            UnixMillis::new(100)
        );
        assert_eq!(
            created.manifest().current().activated_at(),
            Some(UnixMillis::new(100))
        );

        let replay = database
            .store()
            .bootstrap_github_provider_repository(request(desired.clone(), 900))
            .await?;
        assert!(replay.manifest().is_replay());
        assert_eq!(replay.manifest().current(), created.manifest().current());
        assert!(matches!(
            database
                .store()
                .load_current_github_provider_manifest(
                    &TenantScope::from_authenticated_tenant_id("other-tenant")?,
                    connection,
                )
                .await,
            Err(GithubProviderManifestStoreError::NotFound)
        ));

        let repository: (String, String, String, String, i64) = sqlx::query_as(
            r"
            SELECT repository.tenant_id, repository.scm_provider,
                   repository.provider_repository_id,
                   repository.owner || '/' || repository.name,
                   count(policy.repository_id)
            FROM repositories AS repository
            LEFT JOIN repository_publication_policies AS policy
              ON policy.tenant_id = repository.tenant_id
             AND policy.repository_id = repository.id
            WHERE repository.id = $1
            GROUP BY repository.id
            ",
        )
        .bind(desired.repository_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            repository,
            (
                "automata-ci".into(),
                "github".into(),
                "202".into(),
                "automata-ci/automata".into(),
                1,
            )
        );
        let counts: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM github_provider_manifest_revisions),
                (SELECT count(*) FROM github_provider_manifest_current)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (1, 1));

        let rename_error = sqlx::query("UPDATE repositories SET owner = 'other' WHERE id = $1")
            .bind(desired.repository_id().as_uuid())
            .execute(database.pool())
            .await
            .expect_err("manifest-bound canonical identity is immutable");
        assert_eq!(
            rename_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_provider_manifest_repository_identity_immutable")
        );
        let revision_error = sqlx::query(
            "UPDATE github_provider_manifest_revisions SET registered_at_ms = registered_at_ms \
             WHERE provider_connection_id = $1 AND manifest_revision = 1",
        )
        .bind(desired.connection_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("manifest revisions are immutable");
        assert_eq!(
            revision_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_provider_manifest_revisions_immutable")
        );
        let current_error = sqlx::query(
            "DELETE FROM github_provider_manifest_current WHERE provider_connection_id = $1",
        )
        .bind(desired.connection_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("current manifest pointer cannot be removed");
        assert_eq!(
            current_error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("github_provider_manifest_current_removal_forbidden")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn exact_successor_preserves_historical_revision_and_rejects_skips() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("manifest-rotation");
        let connection = connection(0x200);
        let first = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
        );
        database
            .store()
            .bootstrap_github_provider_repository(request(first.clone(), 100))
            .await?;

        let rotated = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(2, 2, 1),
            [8; 32],
            "Automata CI",
        );
        let promoted = database
            .store()
            .bootstrap_github_provider_repository(request(rotated.clone(), 200))
            .await?;
        assert!(!promoted.manifest().is_replay());
        assert_eq!(promoted.manifest().current().manifest(), &rotated);

        let current = database
            .store()
            .load_current_github_provider_manifest(&tenant, connection)
            .await?;
        assert_eq!(current.manifest(), &rotated);
        assert_eq!(current.activated_at(), Some(UnixMillis::new(200)));
        let historical = database
            .store()
            .load_github_provider_manifest_revision(
                &tenant,
                connection,
                GithubProviderManifestRevision::new(1)?,
            )
            .await?;
        assert_eq!(historical.manifest(), &first);
        assert_eq!(historical.registered_at(), UnixMillis::new(100));
        assert_eq!(historical.activated_at(), None);

        let no_evidence_change = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(3, 3, 1),
            [8; 32],
            "Automata CI",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(no_evidence_change, 300))
                .await,
        );
        let skipped_app_evidence = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(3, 4, 1),
            [9; 32],
            "Automata CI",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(skipped_app_evidence, 350))
                .await,
        );
        let skipped = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(4, 3, 2),
            [8; 32],
            "Automata CI / main",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(skipped, 400))
                .await,
        );
        let policy_without_revision = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(3, 2, 1),
            [8; 32],
            "Automata CI / main",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(policy_without_revision, 500))
                .await,
        );
        let stale_time = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(3, 2, 2),
            [8; 32],
            "Automata CI / main",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(stale_time, 199))
                .await,
        );

        let still_current = database
            .store()
            .load_current_github_provider_manifest(&tenant, connection)
            .await?;
        assert_eq!(still_current.manifest(), &rotated);
        let revisions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_provider_manifest_revisions")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(revisions, 2);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn verifier_rotation_and_visibility_transitions_are_independently_revisioned() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("manifest-private-transition");
        let connection = connection(0x250);
        let first = manifest_with_visibility_and_verifier(
            tenant.clone(),
            connection,
            RevisionSet::new(1, 1, 1),
            [7; 32],
            [9; 32],
            "Automata CI",
            "automata-ci/automata",
            ProviderRepositoryVisibility::Public,
        );
        database
            .store()
            .bootstrap_github_provider_repository(request(first, 100))
            .await?;

        let unrevisioned_verifier = manifest_with_visibility_and_verifier(
            tenant.clone(),
            connection,
            RevisionSet::new(2, 1, 1),
            [7; 32],
            [10; 32],
            "Automata CI",
            "automata-ci/automata",
            ProviderRepositoryVisibility::Public,
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(unrevisioned_verifier, 200))
                .await,
        );
        let rotated_verifier = manifest_with_visibility_and_verifier(
            tenant.clone(),
            connection,
            RevisionSet::new(2, 1, 1).with_verifier(2),
            [7; 32],
            [10; 32],
            "Automata CI",
            "automata-ci/automata",
            ProviderRepositoryVisibility::Public,
        );
        database
            .store()
            .bootstrap_github_provider_repository(request(rotated_verifier, 200))
            .await?;

        let unrevisioned_private = manifest_with_visibility_and_verifier(
            tenant.clone(),
            connection,
            RevisionSet::new(3, 1, 1).with_verifier(2),
            [7; 32],
            [10; 32],
            "Automata CI",
            "automata-ci/automata",
            ProviderRepositoryVisibility::Private,
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(unrevisioned_private, 300))
                .await,
        );
        let private = manifest_with_visibility_and_verifier(
            tenant.clone(),
            connection,
            RevisionSet::new(3, 1, 2).with_verifier(2),
            [7; 32],
            [10; 32],
            "Automata CI",
            "automata-ci/automata",
            ProviderRepositoryVisibility::Private,
        );
        database
            .store()
            .bootstrap_github_provider_repository(request(private.clone(), 300))
            .await?;
        let loaded = database
            .store()
            .load_current_github_provider_manifest(&tenant, connection)
            .await?;
        assert_eq!(loaded.manifest(), &private);
        assert_eq!(
            loaded.manifest().repository_visibility(),
            ProviderRepositoryVisibility::Private
        );
        assert_eq!(
            loaded.manifest().source_authentication(),
            "github_app_installation_token"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn same_revision_drift_and_deterministic_repository_collision_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("manifest-drift");
        let connection_id = connection(0x300);
        let desired = manifest(
            tenant.clone(),
            connection_id,
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
        );
        database
            .store()
            .bootstrap_github_provider_repository(request(desired, 100))
            .await?;
        let same_revision_drift = manifest(
            tenant.clone(),
            connection_id,
            RevisionSet::new(1, 1, 1),
            [9; 32],
            "Automata CI",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(same_revision_drift, 200))
                .await,
        );
        let duplicate_repository_connection = manifest(
            tenant.clone(),
            connection(0x302),
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(duplicate_repository_connection, 200))
                .await,
        );

        let collision_tenant = TenantScope::from_authenticated_tenant_id("repository-collision")?;
        let repository_id =
            github_provider_repository_id(&collision_tenant, ProviderRepositoryId::new(202)?);
        sqlx::query(
            r"
            INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
            VALUES ($1, $1, 1, 1)
            ",
        )
        .bind(collision_tenant.as_str())
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'github', '999', 'different', 'repository', 1, 1)
            ",
        )
        .bind(repository_id.as_uuid())
        .bind(collision_tenant.as_str())
        .execute(database.pool())
        .await?;
        let collided = manifest(
            collision_tenant,
            connection(0x301),
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(collided, 200))
                .await,
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn concurrent_replicas_converge_to_one_revision_and_one_replay() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("manifest-replicas");
        let connection = connection(0x400);
        let desired = manifest(
            tenant,
            connection,
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
        );
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let left_request = request(desired.clone(), 100);
        let right_request = request(desired, 101);
        let (left, right) = tokio::join!(
            left_store.bootstrap_github_provider_repository(left_request),
            right_store.bootstrap_github_provider_repository(right_request),
        );
        let left = left?;
        let right = right?;
        assert_ne!(left.manifest().is_replay(), right.manifest().is_replay());
        assert_eq!(left.manifest().current(), right.manifest().current());
        assert!(matches!(
            left.manifest().current().registered_at().get(),
            100 | 101
        ));
        let counts: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM repositories),
                (SELECT count(*) FROM github_provider_manifest_revisions),
                (SELECT count(*) FROM github_provider_manifest_current)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (1, 1, 1));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn minimum_length_canonical_repository_identity_is_durable() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("minimum-name");
        let connection = connection(0x500);
        let desired = manifest_named(
            tenant.clone(),
            connection,
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
            "a/r",
        );
        database
            .store()
            .bootstrap_github_provider_repository(request(desired.clone(), 100))
            .await?;
        let loaded = database
            .store()
            .load_current_github_provider_manifest(&tenant, connection)
            .await?;
        assert_eq!(loaded.manifest(), &desired);
        assert_eq!(loaded.manifest().github_repository_name().as_str(), "a/r");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn sql_canonical_functions_match_rust_golden_and_reject_direct_forgery() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("automata-ci");
        let connection = connection(0x100);
        let desired = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
        );
        database
            .store()
            .bootstrap_github_provider_repository(request(desired.clone(), 100))
            .await?;

        let (sql_repository_id, sql_digest): (Uuid, Vec<u8>) = sqlx::query_as(
            r"
            SELECT
                automata_github_provider_repository_id(
                    revision.tenant_id,
                    revision.github_repository_id
                ),
                automata_github_provider_manifest_digest(revision)
            FROM github_provider_manifest_revisions AS revision
            WHERE revision.provider_connection_id = $1
              AND revision.manifest_revision = 1
            ",
        )
        .bind(connection.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(sql_repository_id, desired.repository_id().as_uuid());
        assert_eq!(
            sql_repository_id.to_string(),
            "93b978d6-eb38-83ec-a919-cfb0b977ca8a"
        );
        assert_eq!(sql_digest, desired.digest().as_bytes().as_slice());
        assert_eq!(
            desired.digest().to_string(),
            "ae2823f2dcda8cf0325e587c50652f8dc17e7e2549e389c7b3ec1eafb9faef00"
        );

        let forged_repository = sqlx::query(
            r"
            INSERT INTO github_provider_manifest_revisions
            SELECT (pg_catalog.jsonb_populate_record(
                revision,
                pg_catalog.jsonb_build_object(
                    'repository_id', $2::TEXT,
                    'provider_connection_id', $3::TEXT
                )
            )).*
            FROM github_provider_manifest_revisions AS revision
            WHERE revision.provider_connection_id = $1
              AND revision.manifest_revision = 1
            ",
        )
        .bind(connection.as_uuid())
        .bind(Uuid::from_u128(0xdead))
        .bind(Uuid::from_u128(0x501))
        .execute(database.pool())
        .await
        .expect_err("direct SQL cannot forge the derived repository UUID");
        assert_constraint(
            &forged_repository,
            "github_provider_manifest_revisions_repository_id_canonical",
        );

        let forged_digest = sqlx::query(
            r"
            INSERT INTO github_provider_manifest_revisions
            SELECT (pg_catalog.jsonb_populate_record(
                revision,
                pg_catalog.jsonb_build_object('provider_connection_id', $2::TEXT)
            )).*
            FROM github_provider_manifest_revisions AS revision
            WHERE revision.provider_connection_id = $1
              AND revision.manifest_revision = 1
            ",
        )
        .bind(connection.as_uuid())
        .bind(Uuid::from_u128(0x502))
        .execute(database.pool())
        .await
        .expect_err("direct SQL cannot forge the canonical manifest digest");
        assert_constraint(
            &forged_digest,
            "github_provider_manifest_revisions_digest_canonical",
        );

        let api_version_mutation = insert_canonical_direct_mutation(
            database.pool(),
            connection,
            Uuid::from_u128(0x503),
            "github_rest_api_version",
            "2022-11-28",
        )
        .await
        .expect_err("a digest-correct REST policy mismatch must fail closed");
        assert_constraint(
            &api_version_mutation,
            "github_provider_manifest_revisions_provider_semantics_exact",
        );
        let visibility_without_private_authority = insert_canonical_direct_mutation(
            database.pool(),
            connection,
            Uuid::from_u128(0x504),
            "repository_visibility",
            "private",
        )
        .await
        .expect_err("private visibility cannot retain anonymous source behavior");
        assert_constraint(
            &visibility_without_private_authority,
            "github_provider_manifest_revisions_provider_semantics_exact",
        );
        let changed_file_bound_mutation = insert_canonical_direct_mutation(
            database.pool(),
            connection,
            Uuid::from_u128(0x505),
            "path_filter_max_changed_files",
            "2999",
        )
        .await
        .expect_err("a digest-correct changed-file policy mismatch must fail closed");
        assert_constraint(
            &changed_file_bound_mutation,
            "github_provider_manifest_revisions_webhook_limits",
        );
        Ok(())
    })
    .await
}

#[derive(Clone, Copy)]
struct RevisionSet {
    manifest: u64,
    app: u64,
    verifier: u64,
    policy: u64,
}

impl RevisionSet {
    const fn new(manifest: u64, app: u64, policy: u64) -> Self {
        Self {
            manifest,
            app,
            verifier: 1,
            policy,
        }
    }

    const fn with_verifier(mut self, verifier: u64) -> Self {
        self.verifier = verifier;
        self
    }
}

fn manifest(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    revisions: RevisionSet,
    spki: [u8; 32],
    check_name: &str,
) -> GithubProviderManifest {
    manifest_named(
        tenant,
        connection,
        revisions,
        spki,
        check_name,
        "automata-ci/automata",
    )
}

fn manifest_named(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    revisions: RevisionSet,
    spki: [u8; 32],
    check_name: &str,
    repository_name: &str,
) -> GithubProviderManifest {
    manifest_with_visibility_and_verifier(
        tenant,
        connection,
        revisions,
        spki,
        [9; 32],
        check_name,
        repository_name,
        ProviderRepositoryVisibility::Public,
    )
}

#[allow(clippy::too_many_arguments)]
fn manifest_with_visibility_and_verifier(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    revisions: RevisionSet,
    spki: [u8; 32],
    verifier_fingerprint: [u8; 32],
    check_name: &str,
    repository_name: &str,
    visibility: ProviderRepositoryVisibility,
) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(revisions.policy);
    GithubProviderManifest::new(
        tenant,
        connection,
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryId::new(202).expect("repository"),
        GithubRepositoryName::new(repository_name).expect("repository name"),
        visibility,
        GithubServerServiceAppId::new(303).expect("App"),
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes(spki),
        GithubServerServiceRevision::new(revisions.app).expect("App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes(
            verifier_fingerprint,
        ))
        .expect("verifier fingerprint"),
        GithubServerServiceRevision::new(revisions.verifier).expect("verifier revision"),
        GithubServerServiceRevision::new(revisions.policy).expect("policy revision"),
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new(check_name).expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(revisions.manifest).expect("manifest revision"),
    )
}

fn request(
    manifest: GithubProviderManifest,
    applied_at_ms: i64,
) -> BootstrapGithubProviderRepository {
    github_manifest_fixture::fixture_github_repository_bootstrap(
        manifest,
        UnixMillis::new(applied_at_ms),
    )
}

fn tenant(value: &str) -> TenantScope {
    TenantScope::from_authenticated_tenant_id(value).expect("tenant")
}

fn connection(value: u128) -> ProviderConnectionId {
    ProviderConnectionId::from_uuid(Uuid::from_u128(value)).expect("connection")
}

fn assert_drift<T>(result: Result<T, GithubProviderManifestStoreError>) {
    assert!(
        result.is_err_and(|error| matches!(
            error,
            GithubProviderManifestStoreError::ConfigurationDrift
        ))
    );
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some(expected),
        "unexpected database error: {error}"
    );
}

async fn insert_canonical_direct_mutation(
    pool: &sqlx::PgPool,
    current_connection: ProviderConnectionId,
    replacement_connection: Uuid,
    field: &str,
    value: &str,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        r"
        WITH candidate AS (
            SELECT pg_catalog.jsonb_populate_record(
                revision,
                pg_catalog.jsonb_build_object(
                    'provider_connection_id', $2::TEXT,
                    $3::TEXT, $4::TEXT
                )
            ) AS value
            FROM github_provider_manifest_revisions AS revision
            WHERE revision.provider_connection_id = $1
              AND revision.manifest_revision = 1
        ), canonical AS (
            SELECT pg_catalog.jsonb_populate_record(
                value,
                pg_catalog.jsonb_build_object(
                    'manifest_digest',
                    automata_github_provider_manifest_digest(value)
                )
            ) AS value
            FROM candidate
        )
        INSERT INTO github_provider_manifest_revisions
        SELECT (value).* FROM canonical
        ",
    )
    .bind(current_connection.as_uuid())
    .bind(replacement_connection)
    .bind(field)
    .bind(value)
    .execute(pool)
    .await
}
