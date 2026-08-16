use automata_ci_provisioning::{
    ApplyWorkspaceEntitlementCommand, AuthorizedApplyWorkspaceEntitlement,
    AuthorizedProvisionWorkspace, ComputeSeconds, DelegatedActorIssuer, DisplayName,
    EntitlementDurationSeconds, EntitlementFailureKind, EntitlementRevision,
    ExternalAccountSubject, OperationId, ProvisionWorkspaceCommand, ProvisioningAuthority,
    ProvisioningAuthorityId, ShardId, WorkspaceEntitlementApplier, WorkspaceExecutionEntitlement,
    WorkspaceId, WorkspaceProvisioner,
};
use automata_ci_provisioning_postgres::{
    PostgresWorkspaceEntitlementApplier, PostgresWorkspaceProvisioner,
};
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

const AUTHORITY: &str = "automata-cloud-production";
const ISSUER: &str = "https://cloud.automata.example";
const SHARD: &str = "prod-us-east-1-001";

fn authority(authority_id: &str) -> ProvisioningAuthority {
    ProvisioningAuthority::new(
        ProvisioningAuthorityId::new(authority_id).expect("authority"),
        ShardId::new(SHARD).expect("shard"),
        DelegatedActorIssuer::new(ISSUER).expect("issuer"),
    )
}

fn provisioning_request(workspace_id: Uuid) -> AuthorizedProvisionWorkspace {
    let command = ProvisionWorkspaceCommand::new(
        OperationId::from_uuid(Uuid::new_v4()).expect("operation ID"),
        ShardId::new(SHARD).expect("shard"),
        WorkspaceId::from_uuid(workspace_id).expect("workspace ID"),
        DisplayName::new("Acme Engineering").expect("workspace name"),
        DelegatedActorIssuer::new(ISSUER).expect("issuer"),
        ExternalAccountSubject::from_uuid(Uuid::new_v4()).expect("subject"),
        DisplayName::new("The Octocat").expect("owner name"),
    );
    AuthorizedProvisionWorkspace::authorize(authority(AUTHORITY), command)
        .expect("authorized provisioning")
}

fn entitlement_request(
    authority_id: &str,
    operation_id: Uuid,
    workspace_id: Uuid,
    revision: u64,
    execution: WorkspaceExecutionEntitlement,
) -> AuthorizedApplyWorkspaceEntitlement {
    let command = ApplyWorkspaceEntitlementCommand::new(
        OperationId::from_uuid(operation_id).expect("operation ID"),
        ShardId::new(SHARD).expect("shard"),
        WorkspaceId::from_uuid(workspace_id).expect("workspace ID"),
        EntitlementRevision::new(revision).expect("revision"),
        execution,
    );
    AuthorizedApplyWorkspaceEntitlement::authorize(authority(authority_id), command)
        .expect("authorized entitlement")
}

fn trial() -> WorkspaceExecutionEntitlement {
    WorkspaceExecutionEntitlement::capped(
        ComputeSeconds::new(6_000).expect("compute"),
        Some(EntitlementDurationSeconds::new(604_800).expect("duration")),
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One scenario proves receipt, revision, and snapshot invariants.
async fn capped_entitlement_is_atomic_replayable_and_revisioned() -> TestResult {
    run_with_database(|database| async move {
        let provisioner = PostgresWorkspaceProvisioner::new(database.pool().clone());
        let applier = PostgresWorkspaceEntitlementApplier::new(database.pool().clone());
        let workspace_id = Uuid::new_v4();
        provisioner
            .provision(provisioning_request(workspace_id))
            .await?;

        let operation_id = Uuid::new_v4();
        let first = applier
            .apply(entitlement_request(
                AUTHORITY,
                operation_id,
                workspace_id,
                1,
                trial(),
            ))
            .await?;
        let replay = applier
            .apply(entitlement_request(
                AUTHORITY,
                operation_id,
                workspace_id,
                1,
                trial(),
            ))
            .await?;
        assert_eq!(replay, first);
        assert_eq!(
            first.expires_at().expect("trial expiry").seconds() - first.applied_at().seconds(),
            604_800
        );

        let operation_conflict = applier
            .apply(entitlement_request(
                AUTHORITY,
                operation_id,
                workspace_id,
                1,
                WorkspaceExecutionEntitlement::capped(
                    ComputeSeconds::new(3_000).expect("compute"),
                    None,
                ),
            ))
            .await
            .expect_err("changed operation semantics must conflict");
        assert_eq!(
            operation_conflict.kind(),
            EntitlementFailureKind::OperationConflict
        );

        let stale = applier
            .apply(entitlement_request(
                AUTHORITY,
                Uuid::new_v4(),
                workspace_id,
                1,
                trial(),
            ))
            .await
            .expect_err("another operation cannot reuse the current revision");
        assert_eq!(stale.kind(), EntitlementFailureKind::StaleRevision);

        let paused = applier
            .apply(entitlement_request(
                AUTHORITY,
                Uuid::new_v4(),
                workspace_id,
                3,
                WorkspaceExecutionEntitlement::Paused,
            ))
            .await?;
        assert_eq!(paused.revision().get(), 3, "revision gaps are allowed");
        assert_eq!(paused.expires_at(), None);

        let persisted: (i64, String, Option<i64>, i64, String) = sqlx::query_as(
            r"
            SELECT revision, policy_kind, compute_limit_ms,
                   consumed_compute_ms, state
            FROM workspace_execution_entitlements
            WHERE workspace_id=$1
            ",
        )
        .bind(workspace_id.hyphenated().to_string())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            persisted,
            (3, "paused".to_owned(), None, 0, "paused".to_owned())
        );

        let counts: (i64, i64) = sqlx::query_as(
            r"
            SELECT
              (SELECT count(*) FROM workspace_entitlement_operations),
              (SELECT count(*) FROM security_audit_events
               WHERE action='workspace.entitlement.applied')
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (2, 2));

        let old_replay = applier
            .apply(entitlement_request(
                AUTHORITY,
                operation_id,
                workspace_id,
                1,
                trial(),
            ))
            .await?;
        assert_eq!(old_replay, first, "old exact receipts remain stable");
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn only_the_workspace_management_authority_can_apply_entitlements() -> TestResult {
    run_with_database(|database| async move {
        let provisioner = PostgresWorkspaceProvisioner::new(database.pool().clone());
        let applier = PostgresWorkspaceEntitlementApplier::new(database.pool().clone());
        let workspace_id = Uuid::new_v4();
        provisioner
            .provision(provisioning_request(workspace_id))
            .await?;

        let wrong_authority = applier
            .apply(entitlement_request(
                "another-control-plane",
                Uuid::new_v4(),
                workspace_id,
                1,
                trial(),
            ))
            .await
            .expect_err("another authority must not manage the workspace");
        assert_eq!(
            wrong_authority.kind(),
            EntitlementFailureKind::WorkspaceUnavailable
        );

        let unmanaged_workspace = applier
            .apply(entitlement_request(
                AUTHORITY,
                Uuid::new_v4(),
                Uuid::new_v4(),
                1,
                trial(),
            ))
            .await
            .expect_err("an unmanaged workspace must not accept external policy");
        assert_eq!(
            unmanaged_workspace.kind(),
            EntitlementFailureKind::WorkspaceUnavailable
        );
        Ok(())
    })
    .await
}
