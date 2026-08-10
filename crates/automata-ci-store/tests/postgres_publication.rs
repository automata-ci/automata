#[allow(dead_code)]
mod common;

use automata_ci_auth::{
    authorization::{OutputVisibility, RepositoryPublicationPolicy},
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRequestId, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_store::{
    PublicationRepositoryError, RepositoryPublicationRepository as _, UpdateRepositoryPublication,
    UpdateRepositoryPublicationOutcome,
};
use sqlx::PgPool;
use tokio::time::{Duration, timeout};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

const TENANT_MANAGEMENT_LOCK_NAMESPACE: i64 = 731_662_009;

struct RepositoryFixture {
    tenant_id: String,
    repository_id: Uuid,
}

struct ActorFixture {
    principal_id: Uuid,
    session_id: Uuid,
    revision: u64,
}

#[derive(Clone, Copy)]
enum DirectGrant {
    None,
    Tenant,
    Repository(Uuid),
}

impl ActorFixture {
    fn actor(&self, tenant_id: &str, request_id: &str) -> ManagementActor {
        ManagementActor::new(
            TenantId::new(tenant_id).expect("tenant"),
            PrincipalId::new(self.principal_id.hyphenated().to_string()).expect("principal"),
            SessionId::new(self.session_id.hyphenated().to_string()).expect("session"),
            ManagementRevision::new(self.revision).expect("revision"),
            Some(ManagementRequestId::new(request_id).expect("request ID")),
            UnixTimestamp::from_seconds(100),
        )
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn public_preferences_are_independent_and_audited() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_repository(&database).await?;
        let actor = seed_actor(&database, &seed.tenant_id, DirectGrant::Tenant).await?;
        let requested = RepositoryPublicationPolicy::new(
            OutputVisibility::Public,
            OutputVisibility::Authenticated,
            OutputVisibility::Public,
        );
        let outcome = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                actor.actor(&seed.tenant_id, "publication-success"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(1)?,
                requested,
            ))
            .await?;
        let UpdateRepositoryPublicationOutcome::Applied(settings) = outcome else {
            return Err("publication update was not applied".into());
        };
        assert_eq!(settings.policy(), requested);
        assert_eq!(settings.revision().value(), 2);

        let durable: (String, String, String, i64, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT dashboard_audience, log_audience, artifact_audience,
                   revision, updated_by_principal_id
            FROM repository_publication_policies
            WHERE tenant_id = $1 AND repository_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            durable,
            (
                "public".to_owned(),
                "authenticated".to_owned(),
                "public".to_owned(),
                2,
                Some(actor.principal_id),
            )
        );

        let audit: (String, String, String, Option<String>) = sqlx::query_as(
            r"
            SELECT action, outcome, resource_kind, request_id
            FROM security_audit_events
            WHERE tenant_id = $1 AND action = 'repository.publication.update'
            ",
        )
        .bind(&seed.tenant_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            audit,
            (
                "repository.publication.update".into(),
                "succeeded".into(),
                "repository-publication".into(),
                Some("publication-success".into()),
            )
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn direct_repository_grant_is_exact_and_does_not_authorize_a_sibling() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_repository(&database).await?;
        let sibling = seed_repository_in_tenant(database.pool(), &seed.tenant_id).await?;
        let actor = seed_actor(
            &database,
            &seed.tenant_id,
            DirectGrant::Repository(seed.repository_id),
        )
        .await?;
        let policy = RepositoryPublicationPolicy::new(
            OutputVisibility::Public,
            OutputVisibility::Authenticated,
            OutputVisibility::Private,
        );

        let exact = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                actor.actor(&seed.tenant_id, "direct-repository-exact"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(1)?,
                policy,
            ))
            .await?;
        assert!(matches!(
            exact,
            UpdateRepositoryPublicationOutcome::Applied(_)
        ));

        let wrong_repository = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                actor.actor(&seed.tenant_id, "direct-repository-wrong"),
                automata_ci_store::RepositoryId::from_uuid(sibling),
                ManagementRevision::new(1)?,
                policy,
            ))
            .await?;
        assert_eq!(
            wrong_repository,
            UpdateRepositoryPublicationOutcome::Forbidden
        );
        assert_eq!(
            policy_revision(database.pool(), &seed.tenant_id, sibling).await?,
            1
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn github_organization_and_team_mappings_honor_tenant_and_exact_repository_scope()
-> TestResult {
    run_with_database(|database| async move {
        let seed = seed_repository(&database).await?;
        let sibling = seed_repository_in_tenant(database.pool(), &seed.tenant_id).await?;
        let repository_principal = Uuid::new_v4();
        let tenant_principal = Uuid::new_v4();
        seed_principal(
            database.pool(),
            &seed.tenant_id,
            repository_principal,
            "601",
        )
        .await?;
        seed_principal(database.pool(), &seed.tenant_id, tenant_principal, "602").await?;
        let repository_role =
            seed_update_role(database.pool(), &seed.tenant_id, repository_principal).await?;
        let tenant_role =
            seed_update_role(database.pool(), &seed.tenant_id, tenant_principal).await?;
        seed_github_mapping(
            database.pool(),
            &seed.tenant_id,
            repository_role,
            7_001,
            None,
            DirectGrant::Repository(seed.repository_id),
        )
        .await?;
        seed_github_mapping(
            database.pool(),
            &seed.tenant_id,
            tenant_role,
            8_001,
            Some(8_002),
            DirectGrant::Tenant,
        )
        .await?;
        seed_github_snapshot(
            database.pool(),
            &seed.tenant_id,
            repository_principal,
            "601",
            90_000,
            200_000,
            Some(7_001),
            None,
        )
        .await?;
        seed_github_snapshot(
            database.pool(),
            &seed.tenant_id,
            tenant_principal,
            "602",
            90_000,
            200_000,
            Some(8_001),
            Some(8_002),
        )
        .await?;
        let repository_actor = seed_session(
            database.pool(),
            &seed.tenant_id,
            repository_principal,
            "601",
        )
        .await?;
        let tenant_actor =
            seed_session(database.pool(), &seed.tenant_id, tenant_principal, "602").await?;
        let policy = RepositoryPublicationPolicy::new(
            OutputVisibility::Public,
            OutputVisibility::Public,
            OutputVisibility::Authenticated,
        );

        let exact_repository = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                repository_actor.actor(&seed.tenant_id, "mapped-repository-exact"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(1)?,
                policy,
            ))
            .await?;
        assert!(matches!(
            exact_repository,
            UpdateRepositoryPublicationOutcome::Applied(_)
        ));
        let wrong_repository = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                repository_actor.actor(&seed.tenant_id, "mapped-repository-wrong"),
                automata_ci_store::RepositoryId::from_uuid(sibling),
                ManagementRevision::new(1)?,
                policy,
            ))
            .await?;
        assert_eq!(
            wrong_repository,
            UpdateRepositoryPublicationOutcome::Forbidden
        );
        let tenant_wide = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                tenant_actor.actor(&seed.tenant_id, "mapped-tenant"),
                automata_ci_store::RepositoryId::from_uuid(sibling),
                ManagementRevision::new(1)?,
                policy,
            ))
            .await?;
        assert!(matches!(
            tenant_wide,
            UpdateRepositoryPublicationOutcome::Applied(_)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn github_mapping_uses_only_the_newest_unexpired_snapshot_without_fallback() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_repository(&database).await?;
        let principal_id = Uuid::new_v4();
        seed_principal(database.pool(), &seed.tenant_id, principal_id, "603").await?;
        let role_id = seed_update_role(database.pool(), &seed.tenant_id, principal_id).await?;
        seed_github_mapping(
            database.pool(),
            &seed.tenant_id,
            role_id,
            9_001,
            None,
            DirectGrant::Tenant,
        )
        .await?;
        seed_github_snapshot(
            database.pool(),
            &seed.tenant_id,
            principal_id,
            "603",
            80_000,
            300_000,
            Some(9_001),
            None,
        )
        .await?;
        let first_actor =
            seed_session(database.pool(), &seed.tenant_id, principal_id, "603").await?;
        let policy = RepositoryPublicationPolicy::new(
            OutputVisibility::Public,
            OutputVisibility::Private,
            OutputVisibility::Private,
        );
        let initial = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                first_actor.actor(&seed.tenant_id, "mapped-current"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(1)?,
                policy,
            ))
            .await?;
        assert!(matches!(
            initial,
            UpdateRepositoryPublicationOutcome::Applied(_)
        ));

        seed_github_snapshot(
            database.pool(),
            &seed.tenant_id,
            principal_id,
            "603",
            90_000,
            300_000,
            None,
            None,
        )
        .await?;
        bump_authorization_revision(database.pool(), &seed.tenant_id, principal_id).await?;
        let empty_actor =
            seed_session(database.pool(), &seed.tenant_id, principal_id, "603").await?;
        let no_fallback = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                empty_actor.actor(&seed.tenant_id, "mapped-newer-empty"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(2)?,
                policy,
            ))
            .await?;
        assert_eq!(no_fallback, UpdateRepositoryPublicationOutcome::Forbidden);

        seed_github_snapshot(
            database.pool(),
            &seed.tenant_id,
            principal_id,
            "603",
            95_000,
            99_000,
            Some(9_001),
            None,
        )
        .await?;
        bump_authorization_revision(database.pool(), &seed.tenant_id, principal_id).await?;
        let expired_actor =
            seed_session(database.pool(), &seed.tenant_id, principal_id, "603").await?;
        let expired = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                expired_actor.actor(&seed.tenant_id, "mapped-newest-expired"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(2)?,
                policy,
            ))
            .await?;
        assert_eq!(expired, UpdateRepositoryPublicationOutcome::Forbidden);
        assert_eq!(
            policy_revision(database.pool(), &seed.tenant_id, seed.repository_id).await?,
            2
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn mapped_role_permission_revocation_serializes_before_publication_authorization()
-> TestResult {
    run_with_database(|database| async move {
        let seed = seed_repository(&database).await?;
        let principal_id = Uuid::new_v4();
        seed_principal(database.pool(), &seed.tenant_id, principal_id, "604").await?;
        let role_id = seed_update_role(database.pool(), &seed.tenant_id, principal_id).await?;
        seed_github_mapping(
            database.pool(),
            &seed.tenant_id,
            role_id,
            10_001,
            None,
            DirectGrant::Tenant,
        )
        .await?;
        seed_github_snapshot(
            database.pool(),
            &seed.tenant_id,
            principal_id,
            "604",
            90_000,
            200_000,
            Some(10_001),
            None,
        )
        .await?;
        let actor = seed_session(database.pool(), &seed.tenant_id, principal_id, "604").await?;

        let mut revoking = database.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
            .bind(&seed.tenant_id)
            .bind(TENANT_MANAGEMENT_LOCK_NAMESPACE)
            .execute(&mut *revoking)
            .await?;
        sqlx::query(
            r"
            DELETE FROM rbac_role_permissions
            WHERE tenant_id = $1 AND role_id = $2
              AND permission_name = 'repositories:visibility:update'
            ",
        )
        .bind(&seed.tenant_id)
        .bind(role_id)
        .execute(&mut *revoking)
        .await?;

        let store = database.store().clone();
        let tenant_id = seed.tenant_id.clone();
        let request = UpdateRepositoryPublication::new(
            actor.actor(&tenant_id, "mapped-permission-revocation-race"),
            automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
            ManagementRevision::new(1)?,
            RepositoryPublicationPolicy::new(
                OutputVisibility::Public,
                OutputVisibility::Public,
                OutputVisibility::Public,
            ),
        );
        let mut update =
            tokio::spawn(async move { store.update_repository_publication(request).await });
        assert!(
            timeout(Duration::from_millis(250), &mut update)
                .await
                .is_err(),
            "publication authorization did not wait for the RBAC mutation mutex"
        );
        revoking.commit().await?;

        let outcome = update.await??;
        assert_eq!(outcome, UpdateRepositoryPublicationOutcome::Forbidden);
        assert_eq!(
            policy_revision(database.pool(), &tenant_id, seed.repository_id).await?,
            1
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn stale_forbidden_cross_tenant_and_revision_races_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_repository(&database).await?;
        let manager = seed_actor(&database, &seed.tenant_id, DirectGrant::Tenant).await?;
        let viewer = seed_actor(&database, &seed.tenant_id, DirectGrant::None).await?;
        let policy = RepositoryPublicationPolicy::new(
            OutputVisibility::Public,
            OutputVisibility::Public,
            OutputVisibility::Public,
        );

        let forbidden = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                viewer.actor(&seed.tenant_id, "publication-forbidden"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(1)?,
                policy,
            ))
            .await?;
        assert_eq!(forbidden, UpdateRepositoryPublicationOutcome::Forbidden);

        let other_tenant = format!("other-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Other', 1, 1)",
        )
        .bind(&other_tenant)
        .execute(database.pool())
        .await?;
        let other_repository = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'github', $3, 'other', 'private', 1, 1)
            ",
        )
        .bind(other_repository)
        .bind(&other_tenant)
        .bind(other_repository.to_string())
        .execute(database.pool())
        .await?;
        let hidden = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                manager.actor(&seed.tenant_id, "publication-hidden"),
                automata_ci_store::RepositoryId::from_uuid(other_repository),
                ManagementRevision::new(1)?,
                policy,
            ))
            .await?;
        assert_eq!(hidden, UpdateRepositoryPublicationOutcome::NotFound);

        let first = UpdateRepositoryPublication::new(
            manager.actor(&seed.tenant_id, "publication-race-a"),
            automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
            ManagementRevision::new(1)?,
            policy,
        );
        let second = UpdateRepositoryPublication::new(
            manager.actor(&seed.tenant_id, "publication-race-b"),
            automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
            ManagementRevision::new(1)?,
            RepositoryPublicationPolicy::default(),
        );
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.update_repository_publication(first),
            right_store.update_repository_publication(second)
        );
        let outcomes = [left?, right?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, UpdateRepositoryPublicationOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    UpdateRepositoryPublicationOutcome::RevisionConflict { .. }
                ))
                .count(),
            1
        );

        sqlx::query(
            "UPDATE tenant_human_memberships SET authorization_revision = authorization_revision + 1 WHERE tenant_id = $1 AND principal_id = $2",
        )
        .bind(&seed.tenant_id)
        .bind(manager.principal_id)
        .execute(database.pool())
        .await?;
        let stale = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                manager.actor(&seed.tenant_id, "publication-stale"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(2)?,
                policy,
            ))
            .await?;
        assert_eq!(stale, UpdateRepositoryPublicationOutcome::SessionStale);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_principal_disable_is_locked_and_observed_before_authorization() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_repository(&database).await?;
        let actor = seed_actor(&database, &seed.tenant_id, DirectGrant::Tenant).await?;
        let mut disabling = database.pool().begin().await?;
        sqlx::query(
            r"
            UPDATE human_principals
            SET status = 'disabled', disabled_at_ms = 100000,
                disabled_reason = 'test disable', updated_at_ms = 100000
            WHERE id = $1
            ",
        )
        .bind(actor.principal_id)
        .execute(&mut *disabling)
        .await?;

        let store = database.store().clone();
        let tenant_id = seed.tenant_id.clone();
        let request = UpdateRepositoryPublication::new(
            actor.actor(&tenant_id, "principal-disable-race"),
            automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
            ManagementRevision::new(1)?,
            RepositoryPublicationPolicy::new(
                OutputVisibility::Public,
                OutputVisibility::Public,
                OutputVisibility::Public,
            ),
        );
        let mut update =
            tokio::spawn(async move { store.update_repository_publication(request).await });
        assert!(
            timeout(Duration::from_millis(250), &mut update)
                .await
                .is_err(),
            "publication authorization did not wait for the principal row lock"
        );
        disabling.commit().await?;

        let outcome = update.await??;
        assert_eq!(outcome, UpdateRepositoryPublicationOutcome::SessionStale);
        assert_eq!(
            policy_revision(database.pool(), &tenant_id, seed.repository_id).await?,
            1
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn failed_audit_append_rolls_back_the_authorized_policy_update() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_repository(&database).await?;
        let actor = seed_actor(&database, &seed.tenant_id, DirectGrant::Tenant).await?;
        sqlx::query(
            r"
            CREATE FUNCTION reject_publication_audit() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit unavailable' USING ERRCODE='check_violation';
            END;
            $$ LANGUAGE plpgsql
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            CREATE TRIGGER reject_publication_audit
            BEFORE INSERT ON security_audit_events
            FOR EACH ROW EXECUTE FUNCTION reject_publication_audit()
            ",
        )
        .execute(database.pool())
        .await?;

        let outcome = database
            .store()
            .update_repository_publication(UpdateRepositoryPublication::new(
                actor.actor(&seed.tenant_id, "publication-audit-rollback"),
                automata_ci_store::RepositoryId::from_uuid(seed.repository_id),
                ManagementRevision::new(1)?,
                RepositoryPublicationPolicy::new(
                    OutputVisibility::Public,
                    OutputVisibility::Public,
                    OutputVisibility::Public,
                ),
            ))
            .await;
        assert_eq!(outcome, Err(PublicationRepositoryError::CorruptData));
        assert_eq!(
            policy_revision(database.pool(), &seed.tenant_id, seed.repository_id).await?,
            1
        );
        let audit_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM security_audit_events WHERE tenant_id = $1")
                .bind(&seed.tenant_id)
                .fetch_one(database.pool())
                .await?;
        assert_eq!(audit_count, 0);
        Ok(())
    })
    .await
}

async fn seed_repository(database: &TestDatabase) -> TestResult<RepositoryFixture> {
    let tenant_id = format!("publication-{}", Uuid::new_v4().simple());
    let repository_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Publication tenant', 1, 1)",
    )
    .bind(&tenant_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', $3, 'automata-ci', 'publication', 1, 1)
        ",
    )
    .bind(repository_id)
    .bind(&tenant_id)
    .bind(repository_id.to_string())
    .execute(database.pool())
    .await?;
    Ok(RepositoryFixture {
        tenant_id,
        repository_id,
    })
}

async fn seed_repository_in_tenant(pool: &PgPool, tenant_id: &str) -> TestResult<Uuid> {
    let repository_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'github', $3, 'automata-ci', $4, 1, 1)
        ",
    )
    .bind(repository_id)
    .bind(tenant_id)
    .bind(repository_id.to_string())
    .bind(format!("publication-{}", repository_id.simple()))
    .execute(pool)
    .await?;
    Ok(repository_id)
}

#[allow(clippy::too_many_lines)]
async fn seed_actor(
    database: &TestDatabase,
    tenant_id: &str,
    grant: DirectGrant,
) -> TestResult<ActorFixture> {
    let principal_id = Uuid::new_v4();
    let provider_subject = principal_id.hyphenated().to_string();
    seed_principal(database.pool(), tenant_id, principal_id, &provider_subject).await?;
    if !matches!(grant, DirectGrant::None) {
        let role_id = seed_update_role(database.pool(), tenant_id, principal_id).await?;
        seed_direct_binding(database.pool(), tenant_id, principal_id, role_id, grant).await?;
    }
    seed_session(database.pool(), tenant_id, principal_id, &provider_subject).await
}

async fn seed_principal(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    provider_subject: &str,
) -> TestResult {
    sqlx::query(
        "INSERT INTO human_principals (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Publication actor', 1, 1)",
    )
    .bind(principal_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id, provider_id, provider_subject, provider_login,
            normalized_login, first_authenticated_at_ms, last_authenticated_at_ms,
            last_observed_at_ms, created_at_ms, updated_at_ms
        ) VALUES ($1, 'github', $2, $3, $3, 1, 1, 1, 1, 1)
        ",
    )
    .bind(principal_id)
    .bind(provider_subject)
    .bind(format!("actor-{}", principal_id.simple()))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO tenant_human_memberships (tenant_id, principal_id, created_at_ms, updated_at_ms) VALUES ($1, $2, 1, 1)",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_update_role(pool: &PgPool, tenant_id: &str, grantor_id: Uuid) -> TestResult<Uuid> {
    let role_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO rbac_roles (
            tenant_id, id, name, display_name, role_kind, immutable,
            created_by_principal_id, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, $3, 'Publication manager', 'custom', FALSE, $4, 1, 1)
        ",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(format!("publication-manager-{}", role_id.simple()))
    .bind(grantor_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO rbac_role_permissions (tenant_id, role_id, permission_name, granted_by_principal_id, granted_at_ms) VALUES ($1, $2, 'repositories:visibility:update', $3, 1)",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(grantor_id)
    .execute(pool)
    .await?;
    Ok(role_id)
}

async fn seed_direct_binding(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    role_id: Uuid,
    grant: DirectGrant,
) -> TestResult {
    let (scope_kind, repository_id) = match grant {
        DirectGrant::None => return Err("cannot seed a binding without a grant".into()),
        DirectGrant::Tenant => ("tenant", None),
        DirectGrant::Repository(repository_id) => ("repository", Some(repository_id)),
    };
    sqlx::query(
        r"
        INSERT INTO rbac_role_bindings (
            tenant_id, id, principal_id, role_id, scope_kind, repository_id,
            assignment_source, created_by_principal_id, created_at_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, 'manual', $3, 1)
        ",
    )
    .bind(tenant_id)
    .bind(Uuid::new_v4())
    .bind(principal_id)
    .bind(role_id)
    .bind(scope_kind)
    .bind(repository_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_github_mapping(
    pool: &PgPool,
    tenant_id: &str,
    role_id: Uuid,
    organization_id: i64,
    team_id: Option<i64>,
    grant: DirectGrant,
) -> TestResult {
    let (scope_kind, repository_id) = match grant {
        DirectGrant::None => return Err("cannot seed a mapping without a grant".into()),
        DirectGrant::Tenant => ("tenant", None),
        DirectGrant::Repository(repository_id) => ("repository", Some(repository_id)),
    };
    let team_slug = team_id.map(|_| "release-engineering");
    sqlx::query(
        r"
        INSERT INTO github_role_mappings (
            tenant_id, id, provider_id, organization_id, organization_login,
            team_id, team_slug, role_id, scope_kind, repository_id,
            status, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, 'github', $3, 'display-name-only', $4, $5, $6, $7, $8,
            'active', 1, 1
        )
        ",
    )
    .bind(tenant_id)
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .bind(team_id)
    .bind(team_slug)
    .bind(role_id)
    .bind(scope_kind)
    .bind(repository_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn seed_github_snapshot(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    provider_subject: &str,
    observed_at_ms: i64,
    valid_until_ms: i64,
    organization_id: Option<i64>,
    team_id: Option<i64>,
) -> TestResult<Uuid> {
    let snapshot_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO github_membership_snapshots (
            tenant_id, id, principal_id, provider_id, provider_subject,
            provider_token_version, observed_at_ms, valid_until_ms
        ) VALUES ($1, $2, $3, 'github', $4, 1, $5, $6)
        ",
    )
    .bind(tenant_id)
    .bind(snapshot_id)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(observed_at_ms)
    .bind(valid_until_ms)
    .execute(pool)
    .await?;
    if let Some(organization_id) = organization_id {
        sqlx::query(
            r"
            INSERT INTO github_organization_membership_observations (
                tenant_id, snapshot_id, organization_id,
                organization_login, membership_role
            ) VALUES ($1, $2, $3, 'renamable-display-only', 'member')
            ",
        )
        .bind(tenant_id)
        .bind(snapshot_id)
        .bind(organization_id)
        .execute(pool)
        .await?;
        if let Some(team_id) = team_id {
            sqlx::query(
                r"
                INSERT INTO github_team_membership_observations (
                    tenant_id, snapshot_id, organization_id, team_id, team_slug
                ) VALUES ($1, $2, $3, $4, 'release-engineering')
                ",
            )
            .bind(tenant_id)
            .bind(snapshot_id)
            .bind(organization_id)
            .bind(team_id)
            .execute(pool)
            .await?;
        }
    } else if team_id.is_some() {
        return Err("team observation requires an organization observation".into());
    }
    Ok(snapshot_id)
}

async fn bump_authorization_revision(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
) -> TestResult {
    sqlx::query(
        r"
        UPDATE tenant_human_memberships
        SET authorization_revision = authorization_revision + 1
        WHERE tenant_id = $1 AND principal_id = $2
        ",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn policy_revision(pool: &PgPool, tenant_id: &str, repository_id: Uuid) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        r"
        SELECT revision
        FROM repository_publication_policies
        WHERE tenant_id = $1 AND repository_id = $2
        ",
    )
    .bind(tenant_id)
    .bind(repository_id)
    .fetch_one(pool)
    .await?)
}

async fn seed_session(
    pool: &PgPool,
    tenant_id: &str,
    principal_id: Uuid,
    provider_subject: &str,
) -> TestResult<ActorFixture> {
    let revision: i64 = sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_one(pool)
    .await?;
    let session_id = Uuid::new_v4();
    let mut token_hash = [0_u8; 32];
    token_hash[..16].copy_from_slice(session_id.as_bytes());
    token_hash[16..].copy_from_slice(session_id.as_bytes());
    sqlx::query(
        r"
        INSERT INTO human_sessions (
            id, tenant_id, principal_id, provider_id, provider_subject,
            session_kind, audience, token_hash, token_hash_key_id,
            authorization_revision, issued_at_ms, last_seen_at_ms,
            idle_expires_at_ms, expires_at_ms
        ) VALUES (
            $1, $2, $3, 'github', $4, 'browser', 'automata.web',
            $5, 'publication-session-v1', $6, 90000, 90000,
            200000, 300000
        )
        ",
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(principal_id)
    .bind(provider_subject)
    .bind(token_hash.as_slice())
    .bind(revision)
    .execute(pool)
    .await?;
    Ok(ActorFixture {
        principal_id,
        session_id,
        revision: u64::try_from(revision)?,
    })
}
