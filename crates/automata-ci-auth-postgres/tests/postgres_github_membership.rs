mod support;

use std::sync::Arc;

use automata_ci_auth::{
    github::{
        GithubMembershipObservation, GithubMembershipRepository, GithubMembershipSnapshot,
        GithubMembershipSnapshotId, GithubOrganizationId, GithubOrganizationLogin,
        GithubOrganizationMembership, GithubOrganizationMembershipRole, GithubTeam, GithubTeamId,
        GithubTeamSlug, PersistGithubMembershipSnapshot, PersistGithubMembershipSnapshotOutcome,
    },
    human::{PrincipalId, ProviderSubject, TenantId},
    time::UnixTimestamp,
    vault::TokenVersion,
};
use automata_ci_auth_postgres::PostgresGithubMembershipRepository;
use sqlx::PgPool;
use uuid::Uuid;

use support::{TestResult, run_with_database};

const PRINCIPAL_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

async fn seed_identity(pool: &PgPool) -> TestResult<Uuid> {
    let principal = Uuid::parse_str(PRINCIPAL_ID)?;
    sqlx::query(
        r"
        INSERT INTO tenants (id,display_name,created_at_ms,updated_at_ms)
        VALUES ('tenant-a','Tenant A',10000,10000),
               ('tenant-b','Tenant B',10000,10000)
        ",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_principals (id,status,display_name,created_at_ms,updated_at_ms)
        VALUES ($1,'active','Viewer',10000,10000)
        ",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_identities (
            principal_id,provider_id,provider_subject,provider_login,normalized_login,
            first_authenticated_at_ms,last_authenticated_at_ms,last_observed_at_ms,
            created_at_ms,updated_at_ms
        ) VALUES ($1,'github','42','octocat','octocat',10000,90000,90000,10000,90000)
        ",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO tenant_human_memberships (
            tenant_id,principal_id,status,created_at_ms,updated_at_ms
        ) VALUES ('tenant-a',$1,'active',10000,10000)
        ",
    )
    .bind(principal)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO human_provider_tokens (
            envelope_record_id,tenant_id,principal_id,provider_id,provider_subject,
            version,grant_kind,token_type,scopes,
            encrypted_payload,payload_nonce,wrapped_data_key,encryption_key_id,encryption_schema,
            issued_at_ms,access_expires_at_ms,created_at_ms,updated_at_ms
        ) VALUES (
            $2,'tenant-a',$1,'github','42',7,'browser_authorization_code','bearer',
            ARRAY['read:org'],$3,$4,$5,'test-kek',1,90000,900000,90000,90000
        )
        ",
    )
    .bind(principal)
    .bind(Uuid::new_v4())
    .bind(vec![1_u8; 17])
    .bind(vec![2_u8; 12])
    .bind(vec![3_u8; 32])
    .execute(pool)
    .await?;
    Ok(principal)
}

fn memberships(
    organization_login: &str,
    team_slug: &str,
    role: GithubOrganizationMembershipRole,
    include_second_team: bool,
) -> GithubMembershipSnapshot {
    let organization_id = GithubOrganizationId::new(100).expect("organization ID");
    let organization_login =
        GithubOrganizationLogin::new(organization_login).expect("organization login");
    let mut teams = vec![GithubTeam::new(
        GithubTeamId::new(200).expect("team ID"),
        organization_id,
        organization_login.clone(),
        GithubTeamSlug::new(team_slug).expect("team slug"),
    )];
    if include_second_team {
        teams.push(GithubTeam::new(
            GithubTeamId::new(201).expect("team ID"),
            organization_id,
            organization_login.clone(),
            GithubTeamSlug::new("release").expect("team slug"),
        ));
    }
    GithubMembershipSnapshot::new(
        [GithubOrganizationMembership::new(
            organization_id,
            organization_login,
            role,
        )],
        teams,
    )
    .expect("snapshot")
}

#[allow(clippy::too_many_arguments)]
fn request(
    tenant_id: &str,
    snapshot_id: Uuid,
    provider_token_version: u64,
    memberships: GithubMembershipSnapshot,
    observed_at: u64,
    valid_until: u64,
) -> PersistGithubMembershipSnapshot {
    PersistGithubMembershipSnapshot::new(
        TenantId::new(tenant_id).expect("tenant"),
        PrincipalId::new(PRINCIPAL_ID).expect("principal"),
        ProviderSubject::new("42").expect("subject"),
        TokenVersion::new(provider_token_version).expect("token version"),
        GithubMembershipObservation::new(
            GithubMembershipSnapshotId::from_uuid(snapshot_id).expect("snapshot ID"),
            memberships,
            UnixTimestamp::from_seconds(observed_at),
            UnixTimestamp::from_seconds(valid_until),
        )
        .expect("observation"),
    )
    .expect("request")
}

async fn revision(pool: &PgPool) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id='tenant-a' AND principal_id=$1",
    )
    .bind(Uuid::parse_str(PRINCIPAL_ID)?)
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn snapshots_are_immutable_idempotent_and_only_stable_authority_bumps_revision() -> TestResult
{
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_identity(pool).await?;
        let repository = PostgresGithubMembershipRepository::new(pool.clone());
        let first_id = Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")?;
        let first = request(
            "tenant-a",
            first_id,
            7,
            memberships(
                "automata-ci",
                "maintainers",
                GithubOrganizationMembershipRole::Member,
                false,
            ),
            100,
            180,
        );
        assert_eq!(
            repository.persist(&first).await?,
            PersistGithubMembershipSnapshotOutcome::Stored {
                authorization_revision: 2,
                authorization_changed: true,
            }
        );
        assert_eq!(
            repository.persist(&first).await?,
            PersistGithubMembershipSnapshotOutcome::AlreadyStored {
                authorization_revision: 2,
            }
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM github_membership_snapshots")
                .fetch_one(pool)
                .await?,
            1
        );

        let renamed = request(
            "tenant-a",
            Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc")?,
            7,
            memberships(
                "renamed-org",
                "renamed-team",
                GithubOrganizationMembershipRole::Admin,
                false,
            ),
            110,
            190,
        );
        assert_eq!(
            repository.persist(&renamed).await?,
            PersistGithubMembershipSnapshotOutcome::Stored {
                authorization_revision: 2,
                authorization_changed: false,
            }
        );
        assert_eq!(revision(pool).await?, 2);
        let names: (String, String) = sqlx::query_as(
            r"
            SELECT organization.organization_login,team.team_slug
            FROM github_organization_membership_observations AS organization
            JOIN github_team_membership_observations AS team
              ON team.tenant_id=organization.tenant_id
             AND team.snapshot_id=organization.snapshot_id
             AND team.organization_id=organization.organization_id
            WHERE organization.snapshot_id=$1
            ",
        )
        .bind(renamed.snapshot_id().as_uuid())
        .fetch_one(pool)
        .await?;
        assert_eq!(names, ("renamed-org".to_owned(), "renamed-team".to_owned()));

        let changed = request(
            "tenant-a",
            Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd")?,
            7,
            memberships(
                "renamed-org",
                "renamed-team",
                GithubOrganizationMembershipRole::Admin,
                true,
            ),
            120,
            200,
        );
        assert_eq!(
            repository.persist(&changed).await?,
            PersistGithubMembershipSnapshotOutcome::Stored {
                authorization_revision: 3,
                authorization_changed: true,
            }
        );
        assert_eq!(revision(pool).await?, 3);

        let conflicting = request(
            "tenant-a",
            first_id,
            7,
            memberships(
                "automata-ci",
                "maintainers",
                GithubOrganizationMembershipRole::Member,
                true,
            ),
            100,
            180,
        );
        assert_eq!(
            repository.persist(&conflicting).await?,
            PersistGithubMembershipSnapshotOutcome::SnapshotConflict
        );
        let out_of_order = request(
            "tenant-a",
            Uuid::new_v4(),
            7,
            memberships(
                "automata-ci",
                "maintainers",
                GithubOrganizationMembershipRole::Member,
                false,
            ),
            115,
            210,
        );
        assert_eq!(
            repository.persist(&out_of_order).await?,
            PersistGithubMembershipSnapshotOutcome::ObservationOutOfOrder
        );
        assert_eq!(revision(pool).await?, 3);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn persistence_requires_exact_active_tenant_identity_and_provider_token_version() -> TestResult
{
    run_with_database(|database| async move {
        let pool = database.pool();
        let principal = seed_identity(pool).await?;
        let repository = PostgresGithubMembershipRepository::new(pool.clone());
        let baseline = |tenant: &str, version: u64| {
            request(
                tenant,
                Uuid::new_v4(),
                version,
                memberships(
                    "automata-ci",
                    "maintainers",
                    GithubOrganizationMembershipRole::Member,
                    false,
                ),
                100,
                180,
            )
        };
        assert_eq!(
            repository.persist(&baseline("tenant-b", 7)).await?,
            PersistGithubMembershipSnapshotOutcome::MembershipNotFound
        );
        assert_eq!(
            repository.persist(&baseline("tenant-a", 6)).await?,
            PersistGithubMembershipSnapshotOutcome::ProviderTokenVersionChanged {
                current_version: TokenVersion::new(7)?,
            }
        );
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='suspended',suspended_at_ms=100000,suspended_reason='test',
                updated_at_ms=100000,revision=revision+1
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(principal)
        .execute(pool)
        .await?;
        assert_eq!(
            repository.persist(&baseline("tenant-a", 7)).await?,
            PersistGithubMembershipSnapshotOutcome::MembershipSuspended
        );
        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status='active',suspended_at_ms=NULL,suspended_reason=NULL,
                updated_at_ms=110000,revision=revision+1
            WHERE tenant_id='tenant-a' AND principal_id=$1
            ",
        )
        .bind(principal)
        .execute(pool)
        .await?;
        sqlx::query(
            r"
            UPDATE human_provider_tokens
            SET version=version+1,revoked_at_ms=110000,revocation_reason='explicit',
                encrypted_payload=NULL,payload_nonce=NULL,wrapped_data_key=NULL,
                encryption_key_id=NULL,encryption_schema=NULL,updated_at_ms=110000
            WHERE tenant_id='tenant-a' AND provider_id='github' AND provider_subject='42'
            ",
        )
        .execute(pool)
        .await?;
        assert_eq!(
            repository.persist(&baseline("tenant-a", 8)).await?,
            PersistGithubMembershipSnapshotOutcome::ProviderTokenRevoked
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM github_membership_snapshots")
                .fetch_one(pool)
                .await?,
            0
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn replica_races_preserve_exact_retry_and_observation_order() -> TestResult {
    run_with_database(|database| async move {
        let pool = database.pool();
        seed_identity(pool).await?;
        let repository = PostgresGithubMembershipRepository::new(pool.clone());
        let first = Arc::new(request(
            "tenant-a",
            Uuid::new_v4(),
            7,
            memberships(
                "automata-ci",
                "maintainers",
                GithubOrganizationMembershipRole::Member,
                false,
            ),
            100,
            180,
        ));
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let [left_task, right_task] = [repository.clone(), repository.clone()].map(|repository| {
            let barrier = Arc::clone(&barrier);
            let first = Arc::clone(&first);
            tokio::spawn(async move {
                barrier.wait().await;
                repository.persist(&first).await
            })
        });
        barrier.wait().await;
        let left = left_task.await??;
        let right = right_task.await??;
        assert!(matches!(
            (&left, &right),
            (
                PersistGithubMembershipSnapshotOutcome::Stored { .. },
                PersistGithubMembershipSnapshotOutcome::AlreadyStored { .. }
            ) | (
                PersistGithubMembershipSnapshotOutcome::AlreadyStored { .. },
                PersistGithubMembershipSnapshotOutcome::Stored { .. }
            )
        ));
        assert_eq!(revision(pool).await?, 2);

        let [left_request, right_request] = [Uuid::new_v4(), Uuid::new_v4()].map(|id| {
            Arc::new(request(
                "tenant-a",
                id,
                7,
                memberships(
                    "automata-ci",
                    "maintainers",
                    GithubOrganizationMembershipRole::Member,
                    false,
                ),
                110,
                190,
            ))
        });
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let left_repository = repository.clone();
        let left_barrier = Arc::clone(&barrier);
        let caller_barrier = Arc::clone(&barrier);
        let left_task = tokio::spawn(async move {
            left_barrier.wait().await;
            left_repository.persist(&left_request).await
        });
        let right_task = tokio::spawn(async move {
            barrier.wait().await;
            repository.persist(&right_request).await
        });
        caller_barrier.wait().await;
        let left = left_task.await??;
        let right = right_task.await??;
        assert!(matches!(
            (&left, &right),
            (
                PersistGithubMembershipSnapshotOutcome::Stored { .. },
                PersistGithubMembershipSnapshotOutcome::ObservationOutOfOrder
            ) | (
                PersistGithubMembershipSnapshotOutcome::ObservationOutOfOrder,
                PersistGithubMembershipSnapshotOutcome::Stored { .. }
            )
        ));
        assert_eq!(revision(pool).await?, 2);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM github_membership_snapshots")
                .fetch_one(pool)
                .await?,
            2
        );
        Ok(())
    })
    .await
}
