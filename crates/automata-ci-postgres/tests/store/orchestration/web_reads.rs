use automata_ci_auth::authorization::{
    AuthorizationContext, AuthorizationRequest, AuthorizationScope, OutputVisibility, Permission,
    RepositoryResource, RepositoryResourceId, RoleName, ScopedRoleGrant, SecretExposureClass,
    repository_read_permissions,
};
use automata_ci_auth::human::{PrincipalId, TenantId};
use automata_ci_core::{
    AttemptId, JobId, LogSequence, LogStreamId, RunId, RunnerRequirements, WorkflowId,
};
use automata_ci_store::{
    HumanArtifactId, HumanArtifactScope, HumanAuthorizationTarget, HumanGitRef, HumanJobScope,
    HumanLiveLogBrowserOrigin, HumanLiveLogScope, HumanLiveLogTicketRepository as _,
    HumanLogSegmentPageSize, HumanLogSegmentQuery, HumanPageSize, HumanRepositoryListQuery,
    HumanRunListQuery, HumanRunPageDirection, HumanRunScope, HumanRunStatusFilter,
    HumanWorkflowListQuery, HumanWorkflowReadRepository as _, IssueHumanLiveLogTicket,
    IssueHumanLiveLogTicketOutcome, RedeemHumanLiveLogTicket, RepositoryCoordinate, RepositoryId,
    StoreError, TenantScope,
};
use std::time::Duration;
use uuid::Uuid;

use crate::support::{TestDatabase, TestResult, run_with_database, seed_control_plane};

use automata_ci_postgres::store::PostgresLiveLogTicketRepository;

#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_field_names)]
struct PublicFixture {
    run_id: RunId,
    job_id: JobId,
    stream_id: LogStreamId,
    artifact_id: HumanArtifactId,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn live_log_tickets_are_origin_bound_and_consumed_once_across_replicas() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        make_repository_navigation_public(&database, &seed.tenant_id, seed.repository_id).await?;
        let fixture = seed_public_completed_run(&database, &seed).await?;
        let attempt_id: Uuid =
            sqlx::query_scalar("SELECT attempt_id FROM attempt_log_streams WHERE id = $1")
                .bind(fixture.stream_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        let scope = HumanLiveLogScope::new(
            TenantScope::from_authenticated_tenant_id(seed.tenant_id.clone())?,
            RepositoryId::from_uuid(seed.repository_id),
            fixture.run_id,
            fixture.job_id,
            AttemptId::from_uuid(attempt_id),
            fixture.stream_id,
        )?;
        let expected_origin = HumanLiveLogBrowserOrigin::new("https://cloud.automata.example")?;
        let wrong_origin = HumanLiveLogBrowserOrigin::new("https://other.automata.example")?;
        let issue = IssueHumanLiveLogTicket::new(
            [7_u8; 32],
            scope.clone(),
            expected_origin.clone(),
            Duration::from_mins(1),
        )?;
        let first = PostgresLiveLogTicketRepository::new(database.pool().clone());
        let second = PostgresLiveLogTicketRepository::new(database.connect_pool(2).await?);
        assert!(matches!(
            first.issue(&issue).await?,
            IssueHumanLiveLogTicketOutcome::Issued(_)
        ));
        assert_eq!(
            second.issue(&issue).await?,
            IssueHumanLiveLogTicketOutcome::DigestCollision
        );
        assert!(
            second
                .redeem(&RedeemHumanLiveLogTicket::new([7_u8; 32], wrong_origin))
                .await?
                .is_none()
        );
        let redeemed = second
            .redeem(&RedeemHumanLiveLogTicket::new(
                [7_u8; 32],
                expected_origin.clone(),
            ))
            .await?
            .expect("the correctly bound replica consumes the ticket");
        assert_eq!(redeemed.scope(), &scope);
        assert!(
            first
                .redeem(&RedeemHumanLiveLogTicket::new([7_u8; 32], expected_origin,))
                .await?
                .is_none()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn tenant_scoped_human_reads_preserve_exact_descriptors_and_visibility() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        make_repository_navigation_public(&database, &seed.tenant_id, seed.repository_id).await?;
        let fixture = seed_public_completed_run(&database, &seed).await?;
        let tenant = TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?;
        let anonymous = AuthorizationContext::anonymous();

        let repository = database
            .store()
            .resolve_repository(
                &tenant,
                &RepositoryCoordinate::new("test", "AUTOMATA", "STORE-TEST")?,
            )
            .await?
            .expect("case-insensitive repository resolution");
        assert_eq!(repository.owner, "automata");
        assert_eq!(repository.name, "store-test");
        assert_eq!(repository.publication.dashboard(), OutputVisibility::Public);
        assert_eq!(repository.publication_revision, 2);

        let repositories = database
            .store()
            .list_repositories(
                &HumanRepositoryListQuery::new(tenant.clone()),
                &anonymous,
                &[permission(repository_read_permissions::REPOSITORY_READ)],
            )
            .await?;
        assert_eq!(repositories.repositories.len(), 1);
        assert_eq!(repositories.repositories[0].id, repository.id);
        assert!(repositories.next_cursor.is_none());

        let workflows = database
            .store()
            .list_workflows(
                &HumanWorkflowListQuery::new(tenant.clone(), repository.id),
                &anonymous,
                &permission(repository_read_permissions::WORKFLOW_READ),
            )
            .await?
            .expect("repository is visible");
        assert_eq!(workflows.workflows.len(), 1);
        assert_eq!(
            workflows.workflows[0]
                .projected_name
                .as_ref()
                .map(|name| name.name.as_str()),
            Some("CI")
        );

        let mut run_query = HumanRunListQuery::new(tenant.clone(), repository.id);
        run_query.workflow_id = Some(WorkflowId::from_uuid(seed.workflow_id));
        run_query.status = Some(HumanRunStatusFilter::Completed);
        run_query.git_ref = Some(HumanGitRef::new("refs/heads/main")?);
        let runs = database
            .store()
            .list_runs(
                &run_query,
                &anonymous,
                &permission(repository_read_permissions::RUN_READ),
            )
            .await?
            .expect("repository is in tenant scope");
        assert_eq!(runs.runs.len(), 1);
        assert_eq!(runs.runs[0].id, fixture.run_id);
        assert_eq!(runs.runs[0].run_number, 2);
        assert_eq!(runs.runs[0].run_attempt, 3);
        assert_eq!(runs.runs[0].workflow_name, "CI");
        assert_eq!(runs.runs[0].actor.as_deref(), Some("octocat"));
        assert_eq!(
            runs.runs[0].publication.effective_dashboard_visibility,
            OutputVisibility::Public
        );

        let run_scope = HumanRunScope::new(tenant.clone(), repository.id, fixture.run_id);
        let detail = database
            .store()
            .get_run(&run_scope)
            .await?
            .expect("run detail");
        assert_eq!(detail.jobs.len(), 1);
        assert_eq!(detail.jobs[0].id, fixture.job_id);
        assert_eq!(
            detail.jobs[0]
                .log_publication
                .as_ref()
                .expect("latest log publication")
                .effective_visibility,
            OutputVisibility::Public
        );
        let job_ir = &detail.jobs[0].job_ir;
        assert_eq!(job_ir.encoded_size(), 128);
        let attempt = detail.jobs[0]
            .latest_attempt
            .as_ref()
            .expect("latest attempt");
        assert_eq!(attempt.number.get(), 1);
        assert_eq!(
            attempt.started_at.map(automata_ci_core::UnixMillis::get),
            Some(13)
        );
        assert_eq!(
            attempt.finished_at.map(automata_ci_core::UnixMillis::get),
            Some(20)
        );
        let terminal = attempt
            .terminal_result
            .as_ref()
            .expect("terminal descriptor");
        assert_eq!(terminal.attempt_id, attempt.id);
        assert_eq!(terminal.descriptor.size(), 3);
        assert_eq!(terminal.descriptor.key().as_str(), "web/results/job-1");
        assert_eq!(detail.artifacts.len(), 1);
        assert_eq!(detail.artifacts[0].id, fixture.artifact_id);

        let job_scope = HumanJobScope::new(
            tenant.clone(),
            repository.id,
            fixture.run_id,
            fixture.job_id,
        );
        let job = database
            .store()
            .get_job(&job_scope)
            .await?
            .expect("job detail");
        assert_eq!(job.navigation.len(), 1);
        assert!(job.navigation[0].conclusion.is_some());
        assert_eq!(
            job.navigation[0]
                .log_publication
                .as_ref()
                .expect("navigation log publication")
                .effective_visibility,
            OutputVisibility::Public
        );
        let stream = job.log_stream.expect("log stream");
        assert_eq!(stream.id, fixture.stream_id);
        assert_eq!(
            stream.publication.secret_exposure,
            SecretExposureClass::Secretless
        );

        let segments = database
            .store()
            .list_log_segments(&HumanLogSegmentQuery {
                scope: job_scope,
                stream_id: fixture.stream_id,
                cursor: None,
                limit: HumanLogSegmentPageSize::new(1)?,
            })
            .await?
            .expect("log segment page");
        assert_eq!(segments.segments.len(), 1);
        assert_eq!(segments.segments[0].first_sequence, LogSequence::new(0));
        assert_eq!(segments.segments[0].last_sequence, LogSequence::new(1));
        assert_eq!(
            segments.segments[0].descriptor.key().as_str(),
            "web/logs/segment-0"
        );
        assert!(segments.segments[0].end_of_stream);
        assert!(segments.newer_cursor.is_none());

        let artifact_scope = HumanArtifactScope {
            tenant: tenant.clone(),
            repository_id: repository.id,
            run_id: fixture.run_id,
            artifact_id: fixture.artifact_id,
            observed_at_seconds: 10,
        };
        let artifact = database
            .store()
            .get_artifact(&artifact_scope)
            .await?
            .expect("finalized unexpired artifact");
        assert_eq!(artifact.blocks.len(), 1);
        assert_eq!(artifact.blocks[0].ordinal, 1);
        assert_eq!(
            artifact.blocks[0].descriptor.key().as_str(),
            "web/artifacts/block-0"
        );
        assert_eq!(artifact.manifest.key().as_str(), "web/artifacts/manifest");

        let artifact_permission = permission(repository_read_permissions::ARTIFACT_DOWNLOAD);
        let artifact_request = AuthorizationRequest::new(
            AuthorizationScope::repository(repository.resource.clone()),
            artifact_permission,
        )
        .with_secret_exposure(artifact.artifact.publication.secret_exposure);
        assert!(
            database
                .store()
                .is_repository_request_allowed(
                    &tenant,
                    repository.id,
                    &anonymous,
                    &HumanAuthorizationTarget::immutable(
                        artifact_request,
                        artifact.artifact.publication.effective_visibility,
                    ),
                )
                .await?
        );

        let mut expired_scope = artifact_scope;
        expired_scope.observed_at_seconds = 1_000;
        assert!(
            database
                .store()
                .get_artifact(&expired_scope)
                .await?
                .is_none()
        );

        let wrong_repository = insert_second_repository(&database, &seed.tenant_id).await?;
        assert!(
            database
                .store()
                .get_run(&HumanRunScope::new(
                    tenant.clone(),
                    wrong_repository,
                    fixture.run_id,
                ))
                .await?
                .is_none()
        );
        let other_tenant = TenantScope::from_authenticated_tenant_id("other-tenant")?;
        assert!(
            database
                .store()
                .get_run(&HumanRunScope::new(
                    other_tenant,
                    repository.id,
                    fixture.run_id,
                ))
                .await?
                .is_none()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn run_keysets_are_stable_and_hidden_rows_do_not_drive_cursors() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        make_repository_navigation_public(&database, &seed.tenant_id, seed.repository_id).await?;
        let tenant = TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?;
        let repository_id = RepositoryId::from_uuid(seed.repository_id);
        let snapshot_id: Uuid =
            sqlx::query_scalar("SELECT snapshot_id FROM workflow_runs WHERE id = $1")
                .bind(seed.run_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        let oldest = RunId::from_uuid(Uuid::parse_str("10000000-0000-0000-0000-000000000001")?);
        let newest = RunId::from_uuid(Uuid::parse_str("20000000-0000-0000-0000-000000000001")?);
        insert_public_queued_run(&database, &seed, snapshot_id, oldest, 2, 50).await?;
        insert_public_queued_run(&database, &seed, snapshot_id, newest, 3, 50).await?;
        insert_private_queued_run(
            &database,
            &seed,
            snapshot_id,
            RunId::from_uuid(Uuid::parse_str("f0000000-0000-0000-0000-000000000001")?),
            4,
            60,
        )
        .await?;

        let anonymous = AuthorizationContext::anonymous();
        let permission = permission(repository_read_permissions::RUN_READ);
        let mut first_query = HumanRunListQuery::new(tenant.clone(), repository_id);
        first_query.limit = HumanPageSize::new(1)?;
        let first = database
            .store()
            .list_runs(&first_query, &anonymous, &permission)
            .await?
            .expect("repository");
        assert_eq!(first.runs[0].id, newest);
        let older = first.older_cursor.expect("authorized older lookahead");

        let mut older_query = first_query.clone();
        older_query.cursor = Some(older);
        older_query.direction = HumanRunPageDirection::Older;
        let second = database
            .store()
            .list_runs(&older_query, &anonymous, &permission)
            .await?
            .expect("older page");
        assert_eq!(second.runs[0].id, oldest);
        assert!(second.older_cursor.is_none());
        let newer_cursor = second.newer_cursor.expect("newer direction");

        let mut newer_query = first_query;
        newer_query.cursor = Some(newer_cursor);
        newer_query.direction = HumanRunPageDirection::Newer;
        let back = database
            .store()
            .list_runs(&newer_query, &anonymous, &permission)
            .await?
            .expect("newer page");
        assert_eq!(back.runs[0].id, newest);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn web_permission_load_rechecks_the_session_authorization_revision() -> TestResult {
    run_with_database(|database| async move {
        let tenant = "web-authz-test";
        let repository_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'Web authz test', 1, 1)",
        )
        .bind(tenant)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'test', $3, 'automata', 'private-repository', 1, 1)
            ",
        )
        .bind(repository_id)
        .bind(tenant)
        .bind(repository_id.to_string())
        .execute(database.pool())
        .await?;
        let principal_id = Uuid::new_v4();
        let role_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO human_principals (
                id, status, display_name, revision, created_at_ms, updated_at_ms
            ) VALUES ($1, 'active', 'Web Viewer', 1, 1, 1)
            ",
        )
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO tenant_human_memberships (
                tenant_id, principal_id, status, authorization_revision,
                revision, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'active', 1, 1, 1, 1)
            ",
        )
        .bind(tenant)
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO rbac_roles (
                tenant_id, id, name, display_name, role_kind, immutable,
                revision, created_by_principal_id, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'web-viewer', 'Web Viewer', 'custom', FALSE,
                      1, $3, 1, 1)
            ",
        )
        .bind(tenant)
        .bind(role_id)
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name,
                granted_by_principal_id, granted_at_ms
            ) VALUES ($1, $2, 'repositories:read', $3, 1)
            ",
        )
        .bind(tenant)
        .bind(role_id)
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO rbac_role_bindings (
                tenant_id, id, principal_id, role_id, scope_kind,
                assignment_source, status, created_by_principal_id,
                created_at_ms, revision
            ) VALUES ($1, $2, $3, $4, 'tenant', 'manual', 'active', $3, 1, 1)
            ",
        )
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(principal_id)
        .bind(role_id)
        .execute(database.pool())
        .await?;
        let revision: i64 = sqlx::query_scalar(
            "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(tenant)
        .bind(principal_id)
        .fetch_one(database.pool())
        .await?;
        let tenant_id = TenantId::new(tenant)?;
        let context = AuthorizationContext::authenticated_at_revision(
            tenant_id.clone(),
            PrincipalId::new(principal_id.to_string())?,
            std::collections::BTreeSet::from([ScopedRoleGrant::new(
                AuthorizationScope::tenant(tenant_id),
                RoleName::new("web-viewer")?,
            )]),
            u64::try_from(revision)?,
        )?;
        let query = HumanRepositoryListQuery::new(TenantScope::from_authenticated_tenant_id(
            tenant,
        )?);
        let repositories = database
            .store()
            .list_repositories(
                &query,
                &context,
                &[permission(repository_read_permissions::REPOSITORY_READ)],
            )
            .await?;
        assert_eq!(repositories.repositories.len(), 1);

        sqlx::query(
            "DELETE FROM rbac_role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_name='repositories:read'",
        )
        .bind(tenant)
        .bind(role_id)
        .execute(database.pool())
        .await?;
        let bumped_revision: i64 = sqlx::query_scalar(
            "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(tenant)
        .bind(principal_id)
        .fetch_one(database.pool())
        .await?;
        assert!(bumped_revision > revision);

        let stale = database
            .store()
            .list_repositories(
                &query,
                &context,
                &[permission(repository_read_permissions::REPOSITORY_READ)],
            )
            .await?;
        assert!(stale.repositories.is_empty());

        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name,
                granted_by_principal_id, granted_at_ms
            ) VALUES ($1, $2, 'secrets:metadata:read', $3, 2)
            ",
        )
        .bind(tenant)
        .bind(role_id)
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        let current_revision: i64 = sqlx::query_scalar(
            "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(tenant)
        .bind(principal_id)
        .fetch_one(database.pool())
        .await?;
        assert!(current_revision > bumped_revision);
        let tenant_id = TenantId::new(tenant)?;
        let current_context = AuthorizationContext::authenticated_at_revision(
            tenant_id.clone(),
            PrincipalId::new(principal_id.to_string())?,
            std::collections::BTreeSet::from([ScopedRoleGrant::new(
                AuthorizationScope::tenant(tenant_id),
                RoleName::new("web-viewer")?,
            )]),
            u64::try_from(current_revision)?,
        )?;
        let secret_metadata = permission("secrets:metadata:read");
        let secret_only = database
            .store()
            .list_repositories(
                &query,
                &current_context,
                std::slice::from_ref(&secret_metadata),
            )
            .await?;
        assert_eq!(secret_only.repositories.len(), 1);
        assert_eq!(secret_only.repositories[0].id.as_uuid(), repository_id);

        let second_repository_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'test', $3, 'zeta', 'secret-repository', 2, 2)
            ",
        )
        .bind(second_repository_id)
        .bind(tenant)
        .bind(second_repository_id.to_string())
        .execute(database.pool())
        .await?;
        let discovery_permissions = [
            permission(repository_read_permissions::REPOSITORY_READ),
            secret_metadata,
        ];
        let mut first_query = HumanRepositoryListQuery::new(
            TenantScope::from_authenticated_tenant_id(tenant)?,
        );
        first_query.limit = HumanPageSize::new(1)?;
        let first = database
            .store()
            .list_repositories(&first_query, &current_context, &discovery_permissions)
            .await?;
        assert_eq!(first.repositories.len(), 1);
        assert_eq!(first.repositories[0].id.as_uuid(), repository_id);
        let cursor = first.next_cursor.expect("union page must retain exact lookahead");

        first_query.cursor = Some(cursor);
        let second = database
            .store()
            .list_repositories(&first_query, &current_context, &discovery_permissions)
            .await?;
        assert_eq!(second.repositories.len(), 1);
        assert_eq!(
            second.repositories[0].id.as_uuid(),
            second_repository_id
        );
        assert!(second.next_cursor.is_none());

        let scoped_binding = sqlx::query(
            r"
            UPDATE rbac_role_bindings
            SET scope_kind = 'repository', repository_id = $1, revision = revision + 1
            WHERE tenant_id = $2 AND principal_id = $3 AND role_id = $4
              AND status = 'active'
            ",
        )
        .bind(second_repository_id)
        .bind(tenant)
        .bind(principal_id)
        .bind(role_id)
        .execute(database.pool())
        .await?;
        assert_eq!(scoped_binding.rows_affected(), 1);
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            )
            SELECT
                format(
                    '10000000-0000-4000-8000-%s',
                    lpad(position::TEXT, 12, '0')
                )::UUID,
                $1,
                'test',
                'hidden-' || position::TEXT,
                'hidden-' || lpad(position::TEXT, 5, '0'),
                'private-repository',
                3,
                3
            FROM generate_series(1, 4097) AS position
            ",
        )
        .bind(tenant)
        .execute(database.pool())
        .await?;
        let scoped_revision: i64 = sqlx::query_scalar(
            "SELECT authorization_revision FROM tenant_human_memberships WHERE tenant_id=$1 AND principal_id=$2",
        )
        .bind(tenant)
        .bind(principal_id)
        .fetch_one(database.pool())
        .await?;
        assert!(scoped_revision > current_revision);
        let tenant_id = TenantId::new(tenant)?;
        let scoped_context = AuthorizationContext::authenticated_at_revision(
            tenant_id.clone(),
            PrincipalId::new(principal_id.to_string())?,
            std::collections::BTreeSet::from([ScopedRoleGrant::new(
                AuthorizationScope::repository(RepositoryResource::new(
                    tenant_id,
                    RepositoryResourceId::from_uuid(second_repository_id)?,
                )),
                RoleName::new("web-viewer")?,
            )]),
            u64::try_from(scoped_revision)?,
        )?;
        let mut bounded_query = HumanRepositoryListQuery::new(
            TenantScope::from_authenticated_tenant_id(tenant)?,
        );
        bounded_query.limit = HumanPageSize::new(1)?;
        let bounded = database
            .store()
            .list_repositories(&bounded_query, &scoped_context, &discovery_permissions)
            .await?;
        assert_eq!(bounded.repositories.len(), 1);
        assert_eq!(
            bounded.repositories[0].id.as_uuid(),
            second_repository_id,
            "repository-scoped discovery must filter hidden rows before keyset pagination"
        );
        assert!(bounded.next_cursor.is_none());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn authenticated_run_reads_require_current_active_actor_authority() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        sqlx::query(
            r"
            UPDATE repository_publication_policies
            SET dashboard_audience = 'authenticated', revision = 2, updated_at_ms = 2
            WHERE tenant_id = $1 AND repository_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(seed.repository_id)
        .execute(database.pool())
        .await?;
        let snapshot_id: Uuid =
            sqlx::query_scalar("SELECT snapshot_id FROM workflow_runs WHERE id = $1")
                .bind(seed.run_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        let authenticated_run = RunId::new();
        insert_queued_run(
            &database,
            &seed,
            snapshot_id,
            authenticated_run,
            2,
            2,
            "authenticated",
        )
        .await?;

        let principal_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO human_principals (
                id, status, display_name, revision, created_at_ms, updated_at_ms
            ) VALUES ($1, 'active', 'Authenticated Viewer', 1, 1, 1)
            ",
        )
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO tenant_human_memberships (
                tenant_id, principal_id, status, authorization_revision,
                revision, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'active', 1, 1, 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(principal_id)
        .execute(database.pool())
        .await?;

        let tenant = TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?;
        let query = HumanRunListQuery::new(tenant, RepositoryId::from_uuid(seed.repository_id));
        let permission = permission(repository_read_permissions::RUN_READ);
        let context = authenticated_context(&seed.tenant_id, principal_id, 1)?;
        let current = database
            .store()
            .list_runs(&query, &context, &permission)
            .await?
            .expect("repository exists");
        assert_eq!(current.runs.len(), 1);
        assert_eq!(current.runs[0].id, authenticated_run);

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET authorization_revision = authorization_revision + 1,
                updated_at_ms = 2
            WHERE tenant_id = $1 AND principal_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        let stale = database
            .store()
            .list_runs(&query, &context, &permission)
            .await?;
        assert!(stale.is_none());

        let current_revision =
            membership_authorization_revision(&database, &seed.tenant_id, principal_id).await?;
        let current_context =
            authenticated_context(&seed.tenant_id, principal_id, current_revision)?;
        let current = database
            .store()
            .list_runs(&query, &current_context, &permission)
            .await?
            .expect("repository exists");
        assert_eq!(current.runs.len(), 1);
        assert_eq!(current.runs[0].id, authenticated_run);

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status = 'suspended', revision = revision + 1,
                updated_at_ms = 3, suspended_at_ms = 3,
                suspended_reason = 'test suspension'
            WHERE tenant_id = $1 AND principal_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        let suspended_revision =
            membership_authorization_revision(&database, &seed.tenant_id, principal_id).await?;
        let suspended_context =
            authenticated_context(&seed.tenant_id, principal_id, suspended_revision)?;
        let suspended = database
            .store()
            .list_runs(&query, &suspended_context, &permission)
            .await?;
        assert!(suspended.is_none());

        sqlx::query(
            r"
            UPDATE tenant_human_memberships
            SET status = 'active', revision = revision + 1,
                updated_at_ms = 4, suspended_at_ms = NULL,
                suspended_reason = NULL
            WHERE tenant_id = $1 AND principal_id = $2
            ",
        )
        .bind(&seed.tenant_id)
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        let reactivated_revision =
            membership_authorization_revision(&database, &seed.tenant_id, principal_id).await?;
        let reactivated_context =
            authenticated_context(&seed.tenant_id, principal_id, reactivated_revision)?;
        let reactivated = database
            .store()
            .list_runs(&query, &reactivated_context, &permission)
            .await?
            .expect("repository exists");
        assert_eq!(reactivated.runs.len(), 1);
        assert_eq!(reactivated.runs[0].id, authenticated_run);

        sqlx::query(
            r"
            UPDATE human_principals
            SET status = 'disabled', revision = revision + 1,
                updated_at_ms = 5, disabled_at_ms = 5,
                disabled_reason = 'test disablement'
            WHERE id = $1
            ",
        )
        .bind(principal_id)
        .execute(database.pool())
        .await?;
        let disabled = database
            .store()
            .list_runs(&query, &reactivated_context, &permission)
            .await?;
        assert!(disabled.is_none());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn duplicate_durable_role_names_fail_closed_before_permission_expansion() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        sqlx::query("ALTER TABLE rbac_roles DROP CONSTRAINT rbac_roles_tenant_name_unique")
            .execute(database.pool())
            .await?;
        let first_role = Uuid::new_v4();
        let second_role = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO rbac_roles (
                tenant_id, id, name, display_name, created_at_ms, updated_at_ms
            ) VALUES
                ($1, $2, 'duplicate-reader', 'First duplicate', 1, 1),
                ($1, $3, 'duplicate-reader', 'Second duplicate', 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(first_role)
        .bind(second_role)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name, granted_at_ms
            ) VALUES ($1, $2, 'workflows:read', 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(first_role)
        .execute(database.pool())
        .await?;

        let tenant_id = TenantId::new(&seed.tenant_id)?;
        let context = AuthorizationContext::authenticated(
            tenant_id.clone(),
            PrincipalId::new(Uuid::new_v4().to_string())?,
            std::collections::BTreeSet::from([ScopedRoleGrant::new(
                AuthorizationScope::tenant(tenant_id),
                RoleName::new("duplicate-reader")?,
            )]),
        )?;
        let query = HumanWorkflowListQuery::new(
            TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?,
            RepositoryId::from_uuid(seed.repository_id),
        );
        assert!(matches!(
            database
                .store()
                .list_workflows(
                    &query,
                    &context,
                    &permission(repository_read_permissions::WORKFLOW_READ),
                )
                .await,
            Err(StoreError::CorruptData(_))
        ));

        sqlx::query("DELETE FROM rbac_roles WHERE tenant_id=$1 AND id=$2")
            .bind(&seed.tenant_id)
            .bind(second_role)
            .execute(database.pool())
            .await?;
        sqlx::query(
            "ALTER TABLE rbac_role_permissions DROP CONSTRAINT rbac_role_permissions_primary_key",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name, granted_at_ms
            ) VALUES ($1, $2, 'workflows:read', 2)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(first_role)
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database
                .store()
                .list_workflows(
                    &query,
                    &context,
                    &permission(repository_read_permissions::WORKFLOW_READ),
                )
                .await,
            Err(StoreError::CorruptData(_))
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn exact_repository_role_overflow_does_not_reveal_target_existence() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        let tenant_id = TenantId::new(&seed.tenant_id)?;
        let mut grants = std::collections::BTreeSet::new();
        for index in 0..=4_096 {
            grants.insert(ScopedRoleGrant::new(
                AuthorizationScope::tenant(tenant_id.clone()),
                RoleName::new(format!("overflow-role-{index}"))?,
            ));
        }
        let context = AuthorizationContext::authenticated(
            tenant_id,
            PrincipalId::new(Uuid::new_v4().to_string())?,
            grants,
        )?;
        let tenant = TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?;
        let permission = permission(repository_read_permissions::WORKFLOW_READ);
        let existing = HumanWorkflowListQuery::new(
            tenant.clone(),
            RepositoryId::from_uuid(seed.repository_id),
        );
        let missing = HumanWorkflowListQuery::new(tenant, RepositoryId::from_uuid(Uuid::new_v4()));

        assert!(matches!(
            database
                .store()
                .list_workflows(&existing, &context, &permission)
                .await,
            Err(StoreError::Operation(_))
        ));
        assert!(matches!(
            database
                .store()
                .list_workflows(&missing, &context, &permission)
                .await,
            Err(StoreError::Operation(_))
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn workflow_authorization_and_rows_share_one_repeatable_read_snapshot() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 0).await?;
        let repository_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO repositories (
                id, tenant_id, scm_provider, provider_repository_id,
                owner, name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'test', $3, 'automata', 'coherent-read', 1, 1)
            ",
        )
        .bind(repository_id)
        .bind(&seed.tenant_id)
        .bind(repository_id.to_string())
        .execute(database.pool())
        .await?;
        let role_id = Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO rbac_roles (
                tenant_id, id, name, display_name, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, 'workflow-reader', 'Workflow reader', 1, 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(role_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO rbac_role_permissions (
                tenant_id, role_id, permission_name, granted_at_ms
            ) VALUES ($1, $2, 'workflows:read', 1)
            ",
        )
        .bind(&seed.tenant_id)
        .bind(role_id)
        .execute(database.pool())
        .await?;
        let tenant_id = TenantId::new(&seed.tenant_id)?;
        let context = AuthorizationContext::authenticated(
            tenant_id.clone(),
            PrincipalId::new(Uuid::new_v4().to_string())?,
            std::collections::BTreeSet::from([ScopedRoleGrant::new(
                AuthorizationScope::tenant(tenant_id),
                RoleName::new("workflow-reader")?,
            )]),
        )?;
        let query = HumanWorkflowListQuery::new(
            TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?,
            RepositoryId::from_uuid(repository_id),
        );
        let permission = permission(repository_read_permissions::WORKFLOW_READ);

        let mut gate = database.pool().begin().await?;
        let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *gate)
            .await?;
        sqlx::query("LOCK TABLE rbac_role_permissions IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *gate)
            .await?;
        let reader_database = database.clone();
        let read = tokio::spawn(async move {
            reader_database
                .store()
                .list_workflows(&query, &context, &permission)
                .await
        });

        let mut observed_blocked_rbac_read = false;
        for _ in 0..200 {
            observed_blocked_rbac_read = sqlx::query_scalar(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity AS activity
                    WHERE activity.datname = current_database()
                      AND $1 = ANY(pg_blocking_pids(activity.pid))
                )
                ",
            )
            .bind(gate_pid)
            .fetch_one(&mut *gate)
            .await?;
            if observed_blocked_rbac_read {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        sqlx::query(
            r"
            DELETE FROM rbac_role_permissions
            WHERE tenant_id = $1 AND role_id = $2
              AND permission_name = 'workflows:read'
            ",
        )
        .bind(&seed.tenant_id)
        .bind(role_id)
        .execute(&mut *gate)
        .await?;
        sqlx::query(
            r"
            INSERT INTO workflow_definitions (
                id, repository_id, path, created_at_ms, updated_at_ms
            ) VALUES ($1, $2, '.ci/workflows/late.yml', 2, 2)
            ",
        )
        .bind(Uuid::new_v4())
        .bind(repository_id)
        .execute(&mut *gate)
        .await?;
        gate.commit().await?;

        let page = read
            .await??
            .expect("repository exists in the read snapshot");
        let permission_still_exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM rbac_role_permissions
                WHERE tenant_id = $1 AND role_id = $2
                  AND permission_name = 'workflows:read'
            )
            ",
        )
        .bind(&seed.tenant_id)
        .bind(role_id)
        .fetch_one(database.pool())
        .await?;
        assert!(
            observed_blocked_rbac_read,
            "the test must interleave after the exact repository snapshot and while RBAC is loading"
        );
        assert!(
            !permission_still_exists,
            "the concurrent revocation committed"
        );
        assert!(
            page.workflows.is_empty(),
            "stale authority must not expose a row committed with its revocation"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn a_stale_prior_lease_log_stream_does_not_poison_the_terminal_job() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fixture = seed_public_completed_run(&database, &seed).await?;
        insert_duplicate_stream(&database, &seed, fixture).await?;
        let scope = HumanJobScope::new(
            TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?,
            RepositoryId::from_uuid(seed.repository_id),
            fixture.run_id,
            fixture.job_id,
        );
        let detail = database
            .store()
            .get_job(&scope)
            .await?
            .expect("terminal job remains readable");
        assert_eq!(detail.job.id, fixture.job_id);
        assert!(detail.log_stream.is_some());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn duplicate_authoritative_log_streams_still_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fixture = seed_public_completed_run(&database, &seed).await?;
        insert_duplicate_authoritative_stream(&database, fixture).await?;
        let scope = HumanJobScope::new(
            TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?,
            RepositoryId::from_uuid(seed.repository_id),
            fixture.run_id,
            fixture.job_id,
        );
        assert!(matches!(
            database.store().get_job(&scope).await,
            Err(StoreError::CorruptData(_))
        ));
        Ok(())
    })
    .await
}

fn permission(name: &str) -> Permission {
    Permission::new(name).expect("canonical read permission")
}

fn authenticated_context(
    tenant: &str,
    principal_id: Uuid,
    authorization_revision: i64,
) -> TestResult<AuthorizationContext> {
    Ok(AuthorizationContext::authenticated_at_revision(
        TenantId::new(tenant)?,
        PrincipalId::new(principal_id.to_string())?,
        std::collections::BTreeSet::new(),
        u64::try_from(authorization_revision)?,
    )?)
}

async fn membership_authorization_revision(
    database: &TestDatabase,
    tenant: &str,
    principal_id: Uuid,
) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        r"
        SELECT authorization_revision
        FROM tenant_human_memberships
        WHERE tenant_id = $1 AND principal_id = $2
        ",
    )
    .bind(tenant)
    .bind(principal_id)
    .fetch_one(database.pool())
    .await?)
}

async fn make_repository_navigation_public(
    database: &TestDatabase,
    tenant_id: &str,
    repository_id: Uuid,
) -> TestResult {
    sqlx::query(
        r"
        UPDATE repository_publication_policies
        SET dashboard_audience = 'public', log_audience = 'public',
            artifact_audience = 'public', revision = 2, updated_at_ms = 2
        WHERE tenant_id = $1 AND repository_id = $2
        ",
    )
    .bind(tenant_id)
    .bind(repository_id)
    .execute(database.pool())
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn seed_public_completed_run(
    database: &TestDatabase,
    seed: &crate::support::SeedData,
) -> TestResult<PublicFixture> {
    let snapshot_id: Uuid =
        sqlx::query_scalar("SELECT snapshot_id FROM workflow_runs WHERE id = $1")
            .bind(seed.run_id.as_uuid())
            .fetch_one(database.pool())
            .await?;
    let run_id = RunId::new();
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id,
            run_number, run_attempt, event_name, event_object_key,
            event_digest, event_size_bytes, event_media_type,
            plan_digest, plan_object_key, plan_size_bytes, plan_media_type,
            plan_schema, head_sha, status, created_at_ms, updated_at_ms,
            workflow_name, git_ref, actor, display_title, commit_subject,
            publication_policy_revision, requested_dashboard_visibility,
            effective_dashboard_visibility, requested_log_visibility,
            requested_artifact_visibility, publication_safety_reason,
            publication_safety_schema, runner_requirements_schema
        ) VALUES (
            $1, $2, $3, $4, 2, 3, 'push', 'web/event',
            decode(repeat('41', 32), 'hex'), 1, 'application/json',
            decode(repeat('42', 32), 'hex'), 'web/plan', 1,
            'application/vnd.automata.workflow-plan.protobuf', 1, $5,
            'completed', 10, 21, 'CI', 'refs/heads/main', 'octocat',
            'Typed dashboard reads', 'Preserve immutable descriptors',
            2, 'public', 'public', 'public', 'public', 'repository_policy', 1, 1
        )
        ",
    )
    .bind(run_id.as_uuid())
    .bind(seed.repository_id)
    .bind(seed.workflow_id)
    .bind(snapshot_id)
    .bind(vec![3_u8; 20])
    .execute(database.pool())
    .await?;

    let job_id = JobId::new();
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        ) VALUES (
            $1, $2, 'verify', 'Verify', $3, 'web/job-ir',
            $4::jsonb,
            1, 1, 128, 11
        )
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id.as_uuid())
    .bind(vec![4_u8; 32])
    .bind(serde_json::to_value(RunnerRequirements::default())?)
    .execute(database.pool())
    .await?;
    let attempt_id = Uuid::new_v4();
    let fence = seed.session_fences[0];
    let lease_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO job_attempts (
            id, job_id, attempt_number, lifecycle, fencing_token,
            lease_id, runner_id, lease_issued_at_ms, lease_expires_at_ms,
            runner_session_id, runner_session_epoch, runner_generation,
            runner_slot, queued_at_ms, changed_at_ms,
            secret_exposure_class, raw_log_disposition,
            requested_log_visibility, effective_log_visibility,
            output_safety_reason, output_safety_schema, classified_at_ms
        ) VALUES (
            $1, $2, 1, 'leased', 1, $3, $4, 13, 100,
            $5, $6, $7, 1, 12, 13,
            'secretless', 'persist', 'public', 'public', 'repository_policy', 1, 12
        )
        ",
    )
    .bind(attempt_id)
    .bind(job_id.as_uuid())
    .bind(lease_id)
    .bind(fence.runner_id().as_uuid())
    .bind(fence.session_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'succeeded', lease_id = NULL, runner_id = NULL,
            lease_issued_at_ms = NULL, lease_expires_at_ms = NULL,
            runner_session_id = NULL, runner_session_epoch = NULL,
            runner_generation = NULL, runner_slot = NULL, changed_at_ms = 20
        WHERE id = $1
        ",
    )
    .bind(attempt_id)
    .execute(database.pool())
    .await?;

    sqlx::query(
        r"
        INSERT INTO attempt_terminal_results (
            attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, result_schema, result_size_bytes,
            result_digest, result_object_key, conclusion,
            completed_at_ms, committed_at_ms, terminal_authority
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 1, $7, 1, 1, 3,
            $8, 'web/results/job-1', 'success', 20, 21, 'runner'
        )
        ",
    )
    .bind(attempt_id)
    .bind(fence.session_id().as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(lease_id)
    .bind(vec![5_u8; 32])
    .execute(database.pool())
    .await?;

    let stream_id = LogStreamId::new();
    sqlx::query(
        r"
        INSERT INTO attempt_log_streams (
            id, attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, log_schema, opened_at_ms, closed_at_ms,
            secret_exposure_class, raw_log_disposition,
            requested_visibility, effective_visibility,
            output_safety_reason, output_safety_schema
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, 1, $8, 1, 1, 15, 21,
            'secretless', 'persist', 'public', 'public', 'repository_policy', 1
        )
        ",
    )
    .bind(stream_id.as_uuid())
    .bind(attempt_id)
    .bind(fence.session_id().as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(lease_id)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO attempt_log_segments (
            stream_id, operation_id, first_sequence, last_sequence,
            object_key, object_digest, encoded_size_bytes,
            uncompressed_size_bytes, stored_at_ms, end_of_stream
        ) VALUES ($1, $2, 0, 1, 'web/logs/segment-0', $3, 8, 16, 21, TRUE)
        ",
    )
    .bind(stream_id.as_uuid())
    .bind(Uuid::new_v4())
    .bind(vec![6_u8; 32])
    .execute(database.pool())
    .await?;

    let artifact_id: i64 = sqlx::query_scalar(
        r"
        INSERT INTO workflow_artifacts (
            upload_id, tenant_id, repository_id, run_id, job_id, attempt_id,
            fencing_token, name, protocol_version, mime_type,
            expires_at_seconds, state, content_digest, content_size_bytes,
            manifest_object_key, manifest_digest, manifest_size_bytes,
            manifest_media_type, created_at_seconds, finalized_at_seconds,
            manifest_state, manifest_reserved_at_seconds,
            finalization_generation, finalization_claimed_size_bytes,
            finalization_claimed_digest, finalization_claim_expires_at_seconds,
            manifest_bytes,
            secret_exposure_class, requested_visibility, effective_visibility,
            publication_safety_reason, publication_safety_schema
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 1, 'coverage', 7,
            'application/octet-stream', 1000, 'finalized', $7, 3,
            'web/artifacts/manifest', $8, 1, 'application/json', 1, 2,
            'ready', 1, 1, 3, $7, 2, $9,
            'secretless', 'public', 'public', 'repository_policy', 1
        ) RETURNING id
        ",
    )
    .bind(Uuid::new_v4())
    .bind(&seed.tenant_id)
    .bind(seed.repository_id)
    .bind(run_id.as_uuid())
    .bind(job_id.as_uuid())
    .bind(attempt_id)
    .bind(vec![7_u8; 32])
    .bind(vec![8_u8; 32])
    .bind(vec![b'{'])
    .fetch_one(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_artifact_blocks (
            artifact_id, block_id, object_key, digest, size_bytes,
            media_type, staged_at_seconds, state, ready_at_seconds
        ) VALUES (
            $1, 'block-0001', 'web/artifacts/block-0', $2, 3,
            'application/octet-stream', 1, 'ready', 2
        )
        ",
    )
    .bind(artifact_id)
    .bind(vec![9_u8; 32])
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_artifact_block_commits (
            artifact_id, list_digest, block_ids, size_bytes, committed_at_seconds
        ) VALUES ($1, $2, ARRAY['block-0001'], 3, 2)
        ",
    )
    .bind(artifact_id)
    .bind(vec![10_u8; 32])
    .execute(database.pool())
    .await?;

    Ok(PublicFixture {
        run_id,
        job_id,
        stream_id,
        artifact_id: HumanArtifactId::new(artifact_id)?,
    })
}

async fn insert_second_repository(
    database: &TestDatabase,
    tenant_id: &str,
) -> TestResult<RepositoryId> {
    let id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'test', $3, 'automata', 'other', 1, 1)
        ",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(id.to_string())
    .execute(database.pool())
    .await?;
    Ok(RepositoryId::from_uuid(id))
}

async fn insert_public_queued_run(
    database: &TestDatabase,
    seed: &crate::support::SeedData,
    snapshot_id: Uuid,
    run_id: RunId,
    run_number: i64,
    created_at: i64,
) -> TestResult {
    insert_queued_run(
        database,
        seed,
        snapshot_id,
        run_id,
        run_number,
        created_at,
        "public",
    )
    .await
}

async fn insert_private_queued_run(
    database: &TestDatabase,
    seed: &crate::support::SeedData,
    snapshot_id: Uuid,
    run_id: RunId,
    run_number: i64,
    created_at: i64,
) -> TestResult {
    insert_queued_run(
        database,
        seed,
        snapshot_id,
        run_id,
        run_number,
        created_at,
        "private",
    )
    .await
}

async fn insert_queued_run(
    database: &TestDatabase,
    seed: &crate::support::SeedData,
    snapshot_id: Uuid,
    run_id: RunId,
    run_number: i64,
    created_at: i64,
    visibility: &str,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id,
            run_number, event_name, event_object_key, event_digest,
            event_size_bytes, event_media_type, plan_digest, plan_object_key,
            plan_size_bytes, plan_media_type, plan_schema, workflow_name, head_sha,
            status, created_at_ms, updated_at_ms,
            requested_dashboard_visibility, effective_dashboard_visibility,
            publication_safety_reason, runner_requirements_schema
        ) VALUES (
            $1, $2, $3, $4, $5, 'push', 'web/keyset-event',
            decode(repeat('43', 32), 'hex'), 1, 'application/json',
            decode(repeat('44', 32), 'hex'), 'web/keyset-plan', 1,
            'application/vnd.automata.workflow-plan.protobuf', 1, 'Keyset', $6,
            'queued', $7, $7, $8, $8, 'repository_policy', 1
        )
        ",
    )
    .bind(run_id.as_uuid())
    .bind(seed.repository_id)
    .bind(seed.workflow_id)
    .bind(snapshot_id)
    .bind(run_number)
    .bind(vec![11_u8; 20])
    .bind(created_at)
    .bind(visibility)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn insert_duplicate_stream(
    database: &TestDatabase,
    seed: &crate::support::SeedData,
    fixture: PublicFixture,
) -> TestResult {
    let attempt_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM job_attempts WHERE job_id = $1 ORDER BY attempt_number DESC LIMIT 1",
    )
    .bind(fixture.job_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let fence = seed.session_fences[0];
    sqlx::query(
        r"
        INSERT INTO attempt_log_streams (
            id, attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, log_schema, opened_at_ms,
            secret_exposure_class, raw_log_disposition,
            requested_visibility, effective_visibility,
            output_safety_reason, output_safety_schema
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, 1, $8, 1, 1, 22,
            'secretless', 'persist', 'public', 'public', 'repository_policy', 1
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(attempt_id)
    .bind(fence.session_id().as_uuid())
    .bind(Uuid::new_v4())
    .bind(fence.runner_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(Uuid::new_v4())
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn insert_duplicate_authoritative_stream(
    database: &TestDatabase,
    fixture: PublicFixture,
) -> TestResult {
    let attempt_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM job_attempts WHERE job_id = $1 ORDER BY attempt_number DESC LIMIT 1",
    )
    .bind(fixture.job_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO attempt_log_streams (
            id, attempt_id, runner_session_id, operation_id, runner_id,
            runner_session_epoch, runner_generation, runner_slot,
            lease_id, fencing_token, log_schema, opened_at_ms,
            secret_exposure_class, raw_log_disposition,
            requested_visibility, effective_visibility,
            output_safety_reason, output_safety_schema
        )
        SELECT $1, terminal.attempt_id, terminal.runner_session_id, $2,
               terminal.runner_id, terminal.runner_session_epoch,
               terminal.runner_generation, terminal.runner_slot,
               terminal.lease_id, terminal.fencing_token, 1, 22,
               'secretless', 'persist', 'public', 'public',
               'repository_policy', 1
        FROM attempt_terminal_results AS terminal
        WHERE terminal.attempt_id = $3
        ",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(attempt_id)
    .execute(database.pool())
    .await?;
    Ok(())
}
