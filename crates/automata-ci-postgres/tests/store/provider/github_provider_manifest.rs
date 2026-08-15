use crate::github_manifest_fixture;

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_store::{
    BootstrapGithubProviderRepository, GithubCheckName, GithubInstallationBindingGeneration,
    GithubProviderGitRef, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision,
    GithubProviderManifestStoreError, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryName, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, ProviderConnectionId,
    ProviderDeliveryIdentity, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility, TenantScope,
    github_provider_repository_id,
};
use uuid::Uuid;

use crate::support::{TestResult, run_with_database, run_with_unmigrated_database};

static PROVIDER_MANIFEST_MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("../automata-ci-store-postgres/migrations");

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
        let before_bootstrap = database_now(database.pool()).await?;
        let created = database
            .store()
            .bootstrap_github_provider_repository(request(desired.clone(), 100))
            .await?;
        let after_bootstrap = database_now(database.pool()).await?;
        assert!(!created.manifest().is_replay());
        assert_eq!(created.manifest().current().manifest(), &desired);
        let registered_at = created.manifest().current().registered_at();
        assert_database_time_bound(registered_at, before_bootstrap, after_bootstrap);
        assert_eq!(created.runtime_policy().registered_at(), registered_at);
        assert!(!created.runtime_policy().is_replay());
        assert_eq!(
            created.manifest().current().activated_at(),
            Some(registered_at)
        );

        let replay = database
            .store()
            .bootstrap_github_provider_repository(request(desired.clone(), 900))
            .await?;
        assert!(replay.manifest().is_replay());
        assert!(replay.runtime_policy().is_replay());
        assert_eq!(replay.runtime_policy().registered_at(), registered_at);
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
        assert!(
            database
                .store()
                .list_current_github_provider_manifests(0)
                .await?
                .is_empty()
        );
        let scheduled_discovery = database
            .store()
            .list_current_github_provider_manifests(1)
            .await?;
        assert_eq!(scheduled_discovery.len(), 1);
        assert_eq!(scheduled_discovery[0].manifest(), &desired);
        assert!(scheduled_discovery[0].is_current());

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
async fn historical_workflow_limit_survives_populated_forward_migration() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        PROVIDER_MANIFEST_MIGRATOR
            .run_to(32, database.pool())
            .await?;
        let tenant = tenant("manifest-workflow-limit-migration");
        let connection = connection(0x133);
        let owner_id = ProviderRepositoryOwnerId::new(404)?;
        let historical = historical_manifest(tenant.clone(), connection, owner_id);
        assert_eq!(historical.limits().workflow_max_bytes(), 1_048_576);
        allow_current_manifest_in_predecessor_fixture(database.pool()).await?;
        let current_seed = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(1, 1, 1),
            [7; 32],
            "Automata CI",
        )
        .with_repository_owner_id(owner_id);

        let created = database
            .store()
            .bootstrap_github_provider_repository(request(current_seed.clone(), 100))
            .await?;
        assert_eq!(created.manifest().current().manifest(), &current_seed);
        rewrite_current_manifest_as_predecessor_history(database.pool(), connection).await?;

        let predecessor_loaded = database
            .store()
            .load_current_github_provider_manifest(&tenant, connection)
            .await?;
        assert_eq!(predecessor_loaded.manifest(), &historical);

        let claimed_at = database_now(database.pool()).await?.get();
        let discovery_id = Uuid::from_u128(0x0001_3301);
        sqlx::query(
            r"
            INSERT INTO github_schedule_discovery_claims (
                discovery_id, tenant_id, repository_id,
                provider_connection_id, manifest_revision, manifest_digest,
                github_repository_owner_id, source_authority_kind,
                private_source_authority_id,
                private_source_authority_identity_digest,
                private_source_authority_app_configuration_revision,
                private_source_authority_policy_revision,
                claim_owner_id, claim_fence, state, claimed_at_ms,
                claim_expires_at_ms, completed_registry_id,
                created_at_ms, updated_at_ms
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 'public_anonymous',
                NULL, NULL, NULL, NULL, $8, 1, 'claimed', $9, $10, NULL, $9, $9
            )
            ",
        )
        .bind(discovery_id)
        .bind(tenant.as_str())
        .bind(historical.repository_id().as_uuid())
        .bind(connection.as_uuid())
        .bind(i64::try_from(historical.revision().get())?)
        .bind(historical.digest().as_bytes().as_slice())
        .bind(i64::try_from(owner_id.get())?)
        .bind(Uuid::from_u128(0x0001_3302))
        .bind(claimed_at)
        .bind(claimed_at + 30_000)
        .execute(database.pool())
        .await?;

        let pointer_before: (String, Uuid, Uuid, i64, Vec<u8>, i64) = sqlx::query_as(
            r"
            SELECT tenant_id, repository_id, provider_connection_id,
                   manifest_revision, manifest_digest, activated_at_ms
            FROM github_provider_manifest_current
            WHERE provider_connection_id = $1
            ",
        )
        .bind(connection.as_uuid())
        .fetch_one(database.pool())
        .await?;
        let evidence_before: (i64, Vec<u8>) = sqlx::query_as(
            "SELECT manifest_revision, manifest_digest \
             FROM github_schedule_discovery_claims WHERE discovery_id = $1",
        )
        .bind(discovery_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(evidence_before.1, historical.digest().as_bytes());

        database.store().migrate().await?;
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 33)",
            )
            .fetch_one(database.pool())
            .await?
        );

        let pointer_after: (String, Uuid, Uuid, i64, Vec<u8>, i64) = sqlx::query_as(
            r"
            SELECT tenant_id, repository_id, provider_connection_id,
                   manifest_revision, manifest_digest, activated_at_ms
            FROM github_provider_manifest_current
            WHERE provider_connection_id = $1
            ",
        )
        .bind(connection.as_uuid())
        .fetch_one(database.pool())
        .await?;
        let evidence_after: (i64, Vec<u8>) = sqlx::query_as(
            "SELECT manifest_revision, manifest_digest \
             FROM github_schedule_discovery_claims WHERE discovery_id = $1",
        )
        .bind(discovery_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(pointer_after, pointer_before);
        assert_eq!(evidence_after, evidence_before);

        let loaded = database
            .store()
            .load_current_github_provider_manifest(&tenant, connection)
            .await?;
        assert_eq!(loaded.manifest(), &historical);
        assert_eq!(loaded.manifest().digest(), historical.digest());
        assert_eq!(loaded.manifest().limits().workflow_max_bytes(), 1_048_576);
        assert!(matches!(
            database
                .store()
                .bootstrap_github_provider_repository(request(historical.clone(), 150))
                .await,
            Err(GithubProviderManifestStoreError::ConfigurationDrift)
        ));
        super::github_subject_evidence::assert_historical_workflow_limit_evidence_round_trip(
            &database,
            &historical,
        )
        .await?;

        let replacement = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(2, 1, 2),
            [7; 32],
            "Automata CI",
        )
        .with_repository_owner_id(owner_id);
        let promoted = database
            .store()
            .bootstrap_github_provider_repository(request(replacement.clone(), 200))
            .await?;
        assert!(!promoted.manifest().is_replay());
        assert_eq!(promoted.manifest().current().manifest(), &replacement);
        let replay = database
            .store()
            .bootstrap_github_provider_repository(request(replacement.clone(), 300))
            .await?;
        assert!(replay.manifest().is_replay());
        let historical_after_successor = database
            .store()
            .load_github_provider_manifest_revision(
                &tenant,
                connection,
                GithubProviderManifestRevision::new(1)?,
            )
            .await?;
        assert_eq!(historical_after_successor.manifest(), &historical);
        assert_eq!(
            historical_after_successor.manifest().digest(),
            historical.digest()
        );
        assert_eq!(
            historical_after_successor
                .manifest()
                .limits()
                .workflow_max_bytes(),
            1_048_576
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
        let created = database
            .store()
            .bootstrap_github_provider_repository(request(first.clone(), 100))
            .await?;
        let first_registered_at = created.manifest().current().registered_at();

        let rotated = manifest(
            tenant.clone(),
            connection,
            RevisionSet::new(2, 2, 1),
            [8; 32],
            "Automata CI",
        );
        let before_promotion = database_now(database.pool()).await?;
        let promoted = database
            .store()
            .bootstrap_github_provider_repository(request(rotated.clone(), 200))
            .await?;
        let after_promotion = database_now(database.pool()).await?;
        assert!(!promoted.manifest().is_replay());
        assert_eq!(promoted.manifest().current().manifest(), &rotated);
        let promoted_at = promoted.manifest().current().registered_at();
        assert_eq!(
            promoted.manifest().current().activated_at(),
            Some(promoted_at)
        );
        assert_database_time_bound(promoted_at, before_promotion, after_promotion);
        assert!(promoted_at >= first_registered_at);

        let current = database
            .store()
            .load_current_github_provider_manifest(&tenant, connection)
            .await?;
        assert_eq!(current.manifest(), &rotated);
        assert_eq!(current.activated_at(), Some(promoted_at));
        let historical = database
            .store()
            .load_github_provider_manifest_revision(
                &tenant,
                connection,
                GithubProviderManifestRevision::new(1)?,
            )
            .await?;
        assert_eq!(historical.manifest(), &first);
        assert_eq!(historical.registered_at(), first_registered_at);
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
#[allow(clippy::too_many_lines)]
async fn installation_replacement_is_contiguous_and_preserves_binding_history() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("manifest-installation-replacement");
        let connection = connection(0x215);
        let skipped_initial = manifest_for_installation(tenant.clone(), connection, 1, 101, 2);
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(skipped_initial, 50))
                .await,
        );
        let first = manifest_for_installation(tenant.clone(), connection, 1, 101, 1);
        database
            .store()
            .bootstrap_github_provider_repository(request(first.clone(), 100))
            .await?;

        for invalid in [
            manifest_for_installation(tenant.clone(), connection, 2, 404, 1),
            manifest_for_installation(tenant.clone(), connection, 2, 404, 3),
            manifest_for_installation(tenant.clone(), connection, 2, 101, 2),
        ] {
            assert_drift(
                database
                    .store()
                    .bootstrap_github_provider_repository(request(invalid, 150))
                    .await,
            );
        }

        let replacement =
            manifest_for_installation_with_policy(tenant.clone(), connection, 2, 404, 2, 2);
        let promoted = database
            .store()
            .bootstrap_github_provider_repository(request(replacement.clone(), 200))
            .await?;
        assert!(!promoted.manifest().is_replay());
        assert_eq!(promoted.manifest().current().manifest(), &replacement);

        let historical = database
            .store()
            .load_github_provider_manifest_revision(
                &tenant,
                connection,
                GithubProviderManifestRevision::new(1)?,
            )
            .await?;
        let current = database
            .store()
            .load_current_github_provider_manifest(&tenant, connection)
            .await?;
        assert_eq!(historical.manifest(), &first);
        assert_eq!(historical.manifest().installation_id().get(), 101);
        assert_eq!(
            historical
                .manifest()
                .installation_binding_generation()
                .get(),
            1
        );
        assert!(!historical.is_current());
        assert_eq!(current.manifest(), &replacement);
        assert_eq!(current.manifest().installation_id().get(), 404);
        assert_eq!(
            current.manifest().installation_binding_generation().get(),
            2
        );
        assert!(current.is_current());
        assert_eq!(
            historical.manifest().repository_id(),
            current.manifest().repository_id()
        );
        let old_delivery = delivery_identity_for_installation(tenant.clone(), connection, 101);
        let replacement_delivery =
            delivery_identity_for_installation(tenant.clone(), connection, 404);
        assert!(
            historical
                .manifest()
                .matches_delivery_identity(&old_delivery)
        );
        assert!(
            !historical
                .manifest()
                .matches_delivery_identity(&replacement_delivery)
        );
        assert!(!current.manifest().matches_delivery_identity(&old_delivery));
        assert!(
            current
                .manifest()
                .matches_delivery_identity(&replacement_delivery)
        );

        let durable: Vec<(i64, i64, i64, Vec<u8>)> = sqlx::query_as(
            r"
            SELECT manifest_revision, provider_installation_id,
                   installation_binding_generation,
                   automata_github_provider_manifest_digest(revision)
            FROM github_provider_manifest_revisions AS revision
            WHERE provider_connection_id = $1
            ORDER BY manifest_revision
            ",
        )
        .bind(connection.as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(durable.len(), 2);
        assert_eq!((durable[0].0, durable[0].1, durable[0].2), (1, 101, 1));
        assert_eq!(durable[0].3, first.digest().as_bytes());
        assert_eq!((durable[1].0, durable[1].1, durable[1].2), (2, 404, 2));
        assert_eq!(durable[1].3, replacement.digest().as_bytes());

        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(first, 250))
                .await,
        );
        let replay = database
            .store()
            .bootstrap_github_provider_repository(request(replacement.clone(), 300))
            .await?;
        assert!(replay.manifest().is_replay());
        assert_eq!(replay.manifest().current().manifest(), &replacement);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn authority_policy_only_rotation_is_a_contiguous_manifest_successor() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("manifest-authority-policy-rotation");
        let connection = connection(0x225);
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
            RevisionSet::new(2, 1, 2).with_runtime(1),
            [7; 32],
            "Automata CI",
        );
        let receipt = database
            .store()
            .bootstrap_github_provider_repository(request(rotated.clone(), 200))
            .await?;
        assert!(!receipt.manifest().is_replay());
        assert_eq!(receipt.manifest().current().manifest(), &rotated);

        let replay = database
            .store()
            .bootstrap_github_provider_repository(request(rotated.clone(), 300))
            .await?;
        assert!(replay.manifest().is_replay());

        let skipped = manifest(
            tenant,
            connection,
            RevisionSet::new(3, 1, 4).with_runtime(1),
            [7; 32],
            "Automata CI",
        );
        assert_drift(
            database
                .store()
                .bootstrap_github_provider_repository(request(skipped, 400))
                .await,
        );
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
        let before_bootstrap = database_now(database.pool()).await?;
        let (left, right) = tokio::join!(
            left_store.bootstrap_github_provider_repository(left_request),
            right_store.bootstrap_github_provider_repository(right_request),
        );
        let after_bootstrap = database_now(database.pool()).await?;
        let left = left?;
        let right = right?;
        assert_ne!(left.manifest().is_replay(), right.manifest().is_replay());
        assert_eq!(
            left.runtime_policy().is_replay(),
            left.manifest().is_replay()
        );
        assert_eq!(
            right.runtime_policy().is_replay(),
            right.manifest().is_replay()
        );
        assert_eq!(left.manifest().current(), right.manifest().current());
        let registered_at = left.manifest().current().registered_at();
        assert_database_time_bound(registered_at, before_bootstrap, after_bootstrap);
        assert_eq!(left.runtime_policy().registered_at(), registered_at);
        assert_eq!(right.runtime_policy().registered_at(), registered_at);
        assert_eq!(
            left.manifest().current().activated_at(),
            Some(registered_at)
        );
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
async fn configured_default_branch_ref_round_trips_with_canonical_digest() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant("nested-default-branch");
        let connection = connection(0x508);
        let desired = manifest_at_ref(
            tenant.clone(),
            connection,
            GithubProviderGitRef::new("refs/heads/refs/release")?,
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
        assert_eq!(loaded.manifest().git_ref(), "refs/heads/refs/release");

        let sql_digest: Vec<u8> = sqlx::query_scalar(
            "SELECT automata_github_provider_manifest_digest(revision) \
             FROM github_provider_manifest_revisions AS revision \
             WHERE provider_connection_id = $1 AND manifest_revision = 1",
        )
        .bind(connection.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(sql_digest, desired.digest().as_bytes());
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT automata_github_provider_git_ref_canonical($1)")
                .bind("refs/heads/refs/release")
                .fetch_one(database.pool())
                .await?
        );
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
            "43c053f02ca6ec9d5fbd2226c608e8eb1b40597f366933d3b5a7a93d997ab4aa"
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
        let zero_binding_generation = insert_canonical_direct_mutation(
            database.pool(),
            connection,
            Uuid::from_u128(0x506),
            "installation_binding_generation",
            "0",
        )
        .await
        .expect_err("a binding generation must stay positive");
        assert_constraint(
            &zero_binding_generation,
            "github_provider_manifest_revisions_positive",
        );
        let unknown_workflow_limit = insert_canonical_direct_mutation(
            database.pool(),
            connection,
            Uuid::from_u128(0x507),
            "workflow_max_bytes",
            "1048575",
        )
        .await
        .expect_err("a digest-correct third workflow limit must fail closed");
        assert_constraint(
            &unknown_workflow_limit,
            "github_provider_manifest_revisions_archive_limits",
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
    runtime: u64,
}

impl RevisionSet {
    const fn new(manifest: u64, app: u64, policy: u64) -> Self {
        Self {
            manifest,
            app,
            verifier: 1,
            policy,
            runtime: policy,
        }
    }

    const fn with_verifier(mut self, verifier: u64) -> Self {
        self.verifier = verifier;
        self
    }

    const fn with_runtime(mut self, runtime: u64) -> Self {
        self.runtime = runtime;
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

fn manifest_at_ref(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    git_ref: GithubProviderGitRef,
) -> GithubProviderManifest {
    manifest_with_selection_and_ref(
        tenant,
        connection,
        RevisionSet::new(1, 1, 1),
        [7; 32],
        [9; 32],
        "Automata CI",
        "automata-ci/automata",
        ProviderRepositoryVisibility::Public,
        GithubProviderWorkflowSelection::all_direct(),
        git_ref,
    )
}

fn historical_manifest(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    owner_id: ProviderRepositoryOwnerId,
) -> GithubProviderManifest {
    let limits = automata_ci_store::adapter_spi::github_provider_manifest_limits(
        automata_ci_store::GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES,
        automata_ci_store::GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS,
        automata_ci_store::GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS,
        automata_ci_store::GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS,
        automata_ci_store::GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES,
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES,
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES,
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES,
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES,
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES,
        automata_ci_store::GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS,
        1_048_576,
    )
    .expect("historical durable manifest limits");
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        tenant,
        connection,
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryId::new(202).expect("repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(303).expect("App"),
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([7; 32]),
        GithubServerServiceRevision::new(1).expect("App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([9; 32]))
            .expect("verifier fingerprint"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
        GithubServerServiceRevision::new(1).expect("policy revision"),
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
        GithubCheckName::new("Automata CI").expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        limits,
        GithubProviderManifestRevision::new(1).expect("manifest revision"),
    )
    .with_repository_owner_id(owner_id)
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
    manifest_with_selection_and_ref(
        tenant,
        connection,
        revisions,
        spki,
        verifier_fingerprint,
        check_name,
        repository_name,
        visibility,
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
    )
}

#[allow(clippy::too_many_arguments)]
fn manifest_with_selection_and_ref(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    revisions: RevisionSet,
    spki: [u8; 32],
    verifier_fingerprint: [u8; 32],
    check_name: &str,
    repository_name: &str,
    visibility: ProviderRepositoryVisibility,
    workflow_selection: GithubProviderWorkflowSelection,
    git_ref: GithubProviderGitRef,
) -> GithubProviderManifest {
    manifest_with_selection_ref_and_installation(
        tenant,
        connection,
        revisions,
        spki,
        verifier_fingerprint,
        check_name,
        repository_name,
        visibility,
        workflow_selection,
        git_ref,
        ProviderInstallationId::new(101).expect("installation"),
        GithubInstallationBindingGeneration::initial(),
    )
}

fn manifest_for_installation(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    manifest_revision: u64,
    installation_id: u64,
    installation_binding_generation: u64,
) -> GithubProviderManifest {
    manifest_for_installation_with_policy(
        tenant,
        connection,
        manifest_revision,
        installation_id,
        installation_binding_generation,
        1,
    )
}

fn manifest_for_installation_with_policy(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    manifest_revision: u64,
    installation_id: u64,
    installation_binding_generation: u64,
    policy_revision: u64,
) -> GithubProviderManifest {
    manifest_with_selection_ref_and_installation(
        tenant,
        connection,
        RevisionSet::new(manifest_revision, 1, policy_revision).with_runtime(1),
        [7; 32],
        [9; 32],
        "Automata CI",
        "automata-ci/automata",
        ProviderRepositoryVisibility::Public,
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
        ProviderInstallationId::new(installation_id).expect("installation"),
        GithubInstallationBindingGeneration::new(installation_binding_generation)
            .expect("installation binding generation"),
    )
}

#[allow(clippy::too_many_arguments)]
fn manifest_with_selection_ref_and_installation(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    revisions: RevisionSet,
    spki: [u8; 32],
    verifier_fingerprint: [u8; 32],
    check_name: &str,
    repository_name: &str,
    visibility: ProviderRepositoryVisibility,
    workflow_selection: GithubProviderWorkflowSelection,
    git_ref: GithubProviderGitRef,
    installation_id: ProviderInstallationId,
    installation_binding_generation: GithubInstallationBindingGeneration,
) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(revisions.runtime);
    GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        tenant,
        connection,
        installation_id,
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
        workflow_selection,
        git_ref,
        GithubCheckName::new(check_name).expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(revisions.manifest).expect("manifest revision"),
    )
    .with_installation_binding_generation(installation_binding_generation)
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

fn delivery_identity_for_installation(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    installation_id: u64,
) -> ProviderDeliveryIdentity {
    ProviderDeliveryIdentity::new(
        tenant,
        "github",
        connection,
        ProviderInstallationId::new(installation_id).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(202).expect("repository"),
            ProviderRepositoryVisibility::Public,
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        "delivery-1",
    )
    .expect("delivery identity")
}

async fn allow_current_manifest_in_predecessor_fixture(pool: &sqlx::PgPool) -> TestResult {
    sqlx::raw_sql(
        r"
        ALTER TABLE ONLY github_provider_manifest_revisions
            DROP CONSTRAINT github_provider_manifest_revisions_archive_limits;
        ALTER TABLE ONLY github_provider_manifest_revisions
            ADD CONSTRAINT github_provider_manifest_revisions_archive_limits CHECK (
                archive_max_compressed_bytes = 268435456
                AND archive_max_decompressed_bytes = 2147483648
                AND archive_max_entries = 100000
                AND archive_max_expanded_bytes = 1073741824
                AND archive_max_entry_path_bytes = 4096
                AND archive_max_workflows = 256
                AND workflow_max_bytes IN (512000, 1048576)
            );
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn rewrite_current_manifest_as_predecessor_history(
    pool: &sqlx::PgPool,
    connection: ProviderConnectionId,
) -> TestResult {
    let mut transaction = pool.begin().await?;
    sqlx::raw_sql(
        r"
        ALTER TABLE ONLY github_provider_manifest_current
            DROP CONSTRAINT github_provider_manifest_current_exact_revision;
        ALTER TABLE github_provider_manifest_revisions
            DISABLE TRIGGER github_provider_manifest_revisions_no_update;
        ALTER TABLE github_provider_manifest_current
            DISABLE TRIGGER github_provider_manifest_current_guard;
        ",
    )
    .execute(&mut *transaction)
    .await?;

    let updated = sqlx::query_scalar::<_, Vec<u8>>(
        r"
        WITH replacement AS (
            SELECT
                revision.provider_connection_id,
                revision.manifest_revision,
                automata_github_provider_manifest_digest(
                    pg_catalog.jsonb_populate_record(
                        revision,
                        pg_catalog.jsonb_build_object(
                            'workflow_max_bytes', 1048576
                        )
                    )
                ) AS manifest_digest
            FROM github_provider_manifest_revisions AS revision
            WHERE revision.provider_connection_id = $1
              AND revision.manifest_revision = 1
        ), updated_revision AS (
            UPDATE github_provider_manifest_revisions AS revision
            SET workflow_max_bytes = 1048576,
                manifest_digest = replacement.manifest_digest
            FROM replacement
            WHERE revision.provider_connection_id = replacement.provider_connection_id
              AND revision.manifest_revision = replacement.manifest_revision
            RETURNING revision.provider_connection_id,
                      revision.manifest_revision,
                      revision.manifest_digest
        )
        UPDATE github_provider_manifest_current AS current_manifest
        SET manifest_digest = updated_revision.manifest_digest
        FROM updated_revision
        WHERE current_manifest.provider_connection_id =
                  updated_revision.provider_connection_id
          AND current_manifest.manifest_revision = updated_revision.manifest_revision
        RETURNING current_manifest.manifest_digest
        ",
    )
    .bind(connection.as_uuid())
    .fetch_one(&mut *transaction)
    .await?;

    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await?;

    sqlx::raw_sql(
        r"
        ALTER TABLE github_provider_manifest_revisions
            ENABLE TRIGGER github_provider_manifest_revisions_no_update;
        ALTER TABLE github_provider_manifest_current
            ENABLE TRIGGER github_provider_manifest_current_guard;
        ALTER TABLE ONLY github_provider_manifest_current
            ADD CONSTRAINT github_provider_manifest_current_exact_revision
            FOREIGN KEY (
                tenant_id, repository_id, provider_connection_id,
                manifest_revision, manifest_digest
            ) REFERENCES github_provider_manifest_revisions (
                tenant_id, repository_id, provider_connection_id,
                manifest_revision, manifest_digest
            ) ON DELETE RESTRICT;
        ALTER TABLE ONLY github_provider_manifest_revisions
            DROP CONSTRAINT github_provider_manifest_revisions_archive_limits;
        ALTER TABLE ONLY github_provider_manifest_revisions
            ADD CONSTRAINT github_provider_manifest_revisions_archive_limits CHECK (
                archive_max_compressed_bytes = 268435456
                AND archive_max_decompressed_bytes = 2147483648
                AND archive_max_entries = 100000
                AND archive_max_expanded_bytes = 1073741824
                AND archive_max_entry_path_bytes = 4096
                AND archive_max_workflows = 256
                AND workflow_max_bytes = 1048576
            );
        ",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let canonical: Vec<u8> = sqlx::query_scalar(
        "SELECT automata_github_provider_manifest_digest(revision) \
         FROM github_provider_manifest_revisions AS revision \
         WHERE provider_connection_id = $1 AND manifest_revision = 1",
    )
    .bind(connection.as_uuid())
    .fetch_one(pool)
    .await?;
    assert_eq!(updated, canonical);
    Ok(())
}

async fn database_now(pool: &sqlx::PgPool) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(pool)
            .await?,
    ))
}

fn assert_database_time_bound(value: UnixMillis, lower: UnixMillis, upper: UnixMillis) {
    assert!(
        value >= lower && value <= upper,
        "database-issued timestamp {value:?} fell outside {lower:?}..={upper:?}"
    );
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
