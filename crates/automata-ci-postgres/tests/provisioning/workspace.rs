use automata_ci_provisioning::{
    AuthorizedProvisionWorkspace, DelegatedActorIssuer, DisplayName, ExternalAccountSubject,
    OperationId, ProvisionWorkspaceCommand, ProvisioningAuthority, ProvisioningAuthorityId,
    ProvisioningFailureKind, ShardId, WorkspaceId, WorkspaceProvisioner,
};
use automata_ci_provisioning_postgres::PostgresWorkspaceProvisioner;
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

const ISSUER: &str = "https://cloud.automata.example";
const SHARD: &str = "prod-us-east-1-001";

fn authorized_request(
    operation_id: Uuid,
    workspace_id: Uuid,
    workspace_name: &str,
    subject: Uuid,
) -> AuthorizedProvisionWorkspace {
    let issuer = DelegatedActorIssuer::new(ISSUER).expect("issuer");
    let authority = ProvisioningAuthority::new(
        ProvisioningAuthorityId::new("automata-cloud-production").expect("authority"),
        ShardId::new(SHARD).expect("shard"),
        issuer.clone(),
    );
    let command = ProvisionWorkspaceCommand::new(
        OperationId::from_uuid(operation_id).expect("operation ID"),
        ShardId::new(SHARD).expect("shard"),
        WorkspaceId::from_uuid(workspace_id).expect("workspace ID"),
        DisplayName::new(workspace_name).expect("workspace name"),
        issuer,
        ExternalAccountSubject::from_uuid(subject).expect("subject"),
        DisplayName::new("The Octocat").expect("owner name"),
    );
    AuthorizedProvisionWorkspace::authorize(authority, command).expect("authorized command")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn provisioning_is_atomic_replayable_and_conflict_safe() -> TestResult {
    run_with_database(|database| async move {
        let provisioner = PostgresWorkspaceProvisioner::new(database.pool().clone());
        let operation_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let subject = Uuid::new_v4();

        let first = provisioner
            .provision(authorized_request(
                operation_id,
                workspace_id,
                "Acme Engineering",
                subject,
            ))
            .await?;
        let replay = provisioner
            .provision(authorized_request(
                operation_id,
                workspace_id,
                "Acme Engineering",
                subject,
            ))
            .await?;
        assert_eq!(replay, first);

        let operation_conflict = provisioner
            .provision(authorized_request(
                operation_id,
                workspace_id,
                "Changed name",
                subject,
            ))
            .await
            .expect_err("changed operation semantics must fail");
        assert_eq!(
            operation_conflict.kind(),
            ProvisioningFailureKind::OperationConflict
        );

        let workspace_conflict = provisioner
            .provision(authorized_request(
                Uuid::new_v4(),
                workspace_id,
                "Acme Engineering",
                subject,
            ))
            .await
            .expect_err("a second operation must not own the workspace");
        assert_eq!(
            workspace_conflict.kind(),
            ProvisioningFailureKind::WorkspaceConflict
        );

        let counts: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM workspace_provisioning_operations),
              (SELECT count(*) FROM tenants),
              (SELECT count(*) FROM delegated_actor_identities),
              (SELECT count(*) FROM tenant_human_memberships),
              (SELECT count(*) FROM workspace_management_bindings),
              (SELECT count(*) FROM security_audit_events
               WHERE action='workspace.provisioned')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (1, 1, 1, 1, 1, 1));

        let role_permission_counts: (i64, i64) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM rbac_permissions),
              (SELECT count(*) FROM rbac_role_permissions
               WHERE tenant_id=$1)
            ",
        )
        .bind(workspace_id.hyphenated().to_string())
        .fetch_one(database.pool())
        .await?;
        assert!(role_permission_counts.0 > 0);
        assert_eq!(role_permission_counts.1, role_permission_counts.0);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_workspaces_reuse_one_external_principal() -> TestResult {
    run_with_database(|database| async move {
        let provisioner = PostgresWorkspaceProvisioner::new(database.pool().clone());
        let subject = Uuid::new_v4();
        let first_request =
            authorized_request(Uuid::new_v4(), Uuid::new_v4(), "Acme Engineering", subject);
        let second_request =
            authorized_request(Uuid::new_v4(), Uuid::new_v4(), "Example Labs", subject);

        let (first, second) = tokio::join!(
            provisioner.provision(first_request),
            provisioner.provision(second_request)
        );
        let first = first?;
        let second = second?;
        assert_eq!(
            first.initial_owner_principal_id(),
            second.initial_owner_principal_id()
        );

        let counts: (i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM human_principals),
              (SELECT count(*) FROM delegated_actor_identities),
              (SELECT count(*) FROM tenants),
              (SELECT count(*) FROM tenant_human_memberships)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (1, 1, 2, 2));
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn a_disabled_mapped_principal_cannot_receive_another_workspace() -> TestResult {
    run_with_database(|database| async move {
        let provisioner = PostgresWorkspaceProvisioner::new(database.pool().clone());
        let subject = Uuid::new_v4();
        let first = provisioner
            .provision(authorized_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "Acme Engineering",
                subject,
            ))
            .await?;
        sqlx::query(
            r"
            UPDATE human_principals
            SET status='disabled', disabled_at_ms=updated_at_ms,
                disabled_reason='test disable', revision=revision+1
            WHERE id=$1
            ",
        )
        .bind(first.initial_owner_principal_id().as_uuid())
        .execute(database.pool())
        .await?;

        let failure = provisioner
            .provision(authorized_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "Blocked workspace",
                subject,
            ))
            .await
            .expect_err("disabled principal must fail closed");
        assert_eq!(
            failure.kind(),
            ProvisioningFailureKind::PrincipalUnavailable
        );
        let workspace_count: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants")
            .fetch_one(database.pool())
            .await?;
        assert_eq!(workspace_count, 1);
        Ok(())
    })
    .await
}
