use automata_ci_postgres::provisioning::{
    PostgresWorkspaceEntitlementApplier, PostgresWorkspaceProvisioner,
    PostgresWorkspaceUsageExporter,
};
use automata_ci_provisioning::{
    ApplyWorkspaceEntitlementCommand, AuthorizedApplyWorkspaceEntitlement,
    AuthorizedListWorkspaceUsage, AuthorizedProvisionWorkspace, DelegatedActorIssuer, DisplayName,
    EntitlementRevision, ExternalAccountSubject, ListWorkspaceUsageCommand, OperationId,
    ProvisionWorkspaceCommand, ProvisioningAuthority, ProvisioningAuthorityId, ShardId,
    UsageExportCursor, UsageExportFailureKind, UsageExportPageSize, WorkspaceEntitlementApplier,
    WorkspaceExecutionEntitlement, WorkspaceId, WorkspaceProvisioner, WorkspaceUsageExporter,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

const AUTHORITY_A: &str = "automata-cloud-production";
const AUTHORITY_B: &str = "partner-control-plane";
const ISSUER: &str = "https://cloud.automata.example";
const SHARD: &str = "prod-us-east-1-001";

fn authority(authority_id: &str) -> ProvisioningAuthority {
    ProvisioningAuthority::new(
        ProvisioningAuthorityId::new(authority_id).expect("authority"),
        ShardId::new(SHARD).expect("shard"),
        DelegatedActorIssuer::new(ISSUER).expect("issuer"),
    )
}

fn provisioning_request(authority_id: &str, workspace_id: Uuid) -> AuthorizedProvisionWorkspace {
    let command = ProvisionWorkspaceCommand::new(
        OperationId::from_uuid(Uuid::new_v4()).expect("operation ID"),
        ShardId::new(SHARD).expect("shard"),
        WorkspaceId::from_uuid(workspace_id).expect("workspace ID"),
        DisplayName::new("Acme Engineering").expect("workspace name"),
        DelegatedActorIssuer::new(ISSUER).expect("issuer"),
        ExternalAccountSubject::from_uuid(Uuid::new_v4()).expect("subject"),
        DisplayName::new("The Octocat").expect("owner name"),
    );
    AuthorizedProvisionWorkspace::authorize(authority(authority_id), command)
        .expect("authorized provisioning")
}

fn entitlement_request(
    authority_id: &str,
    workspace_id: Uuid,
) -> AuthorizedApplyWorkspaceEntitlement {
    let command = ApplyWorkspaceEntitlementCommand::new(
        OperationId::from_uuid(Uuid::new_v4()).expect("operation ID"),
        ShardId::new(SHARD).expect("shard"),
        WorkspaceId::from_uuid(workspace_id).expect("workspace ID"),
        EntitlementRevision::new(1).expect("revision"),
        WorkspaceExecutionEntitlement::Uncapped,
    );
    AuthorizedApplyWorkspaceEntitlement::authorize(authority(authority_id), command)
        .expect("authorized entitlement")
}

fn export_request(
    authority_id: &str,
    cursor: UsageExportCursor,
    page_size: u32,
) -> AuthorizedListWorkspaceUsage {
    let command = ListWorkspaceUsageCommand::new(
        ShardId::new(SHARD).expect("shard"),
        cursor,
        UsageExportPageSize::new(page_size).expect("page size"),
    );
    AuthorizedListWorkspaceUsage::authorize(authority(authority_id), command)
        .expect("authorized usage export")
}

#[derive(Clone, Copy)]
struct UsageFixture {
    authority_id: &'static str,
    workspace_id: Uuid,
    event_id: Uuid,
    attempt_id: Uuid,
    start_ms: i64,
    end_ms: i64,
    consumed_ms: i64,
}

async fn insert_usage(pool: &PgPool, usage: UsageFixture) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
        INSERT INTO workspace_usage_events (
            event_id, authority_id, shard_id, workspace_id, attempt_id,
            entitlement_revision, interval_start_ms, interval_end_ms,
            consumed_compute_ms, recorded_at_ms
        ) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,$7)
        ",
    )
    .bind(usage.event_id)
    .bind(usage.authority_id)
    .bind(SHARD)
    .bind(usage.workspace_id.hyphenated().to_string())
    .bind(usage.attempt_id)
    .bind(usage.start_ms)
    .bind(usage.end_ms)
    .bind(usage.consumed_ms)
    .execute(pool)
    .await?;
    Ok(())
}

async fn provision_entitled_workspace(
    pool: &PgPool,
    authority_id: &'static str,
) -> TestResult<Uuid> {
    let workspace_id = Uuid::new_v4();
    PostgresWorkspaceProvisioner::new(pool.clone())
        .provision(provisioning_request(authority_id, workspace_id))
        .await?;
    PostgresWorkspaceEntitlementApplier::new(pool.clone())
        .apply(entitlement_request(authority_id, workspace_id))
        .await?;
    Ok(workspace_id)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn usage_pages_are_stable_replayable_and_append_visible() -> TestResult {
    run_with_database(|database| async move {
        let workspace_id = provision_entitled_workspace(database.pool(), AUTHORITY_A).await?;
        let attempt_id = Uuid::new_v4();
        let event_ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        for (index, event_id) in event_ids.into_iter().enumerate() {
            let start_ms = 1_786_500_100_000 + i64::try_from(index)? * 1_000;
            insert_usage(
                database.pool(),
                UsageFixture {
                    authority_id: AUTHORITY_A,
                    workspace_id,
                    event_id,
                    attempt_id,
                    start_ms,
                    end_ms: start_ms + 1_000,
                    consumed_ms: 1_000,
                },
            )
            .await?;
        }

        let exporter = PostgresWorkspaceUsageExporter::new(database.pool().clone());
        let first = exporter
            .list(export_request(
                AUTHORITY_A,
                UsageExportCursor::beginning(),
                2,
            ))
            .await?;
        let replay = exporter
            .list(export_request(
                AUTHORITY_A,
                UsageExportCursor::beginning(),
                2,
            ))
            .await?;
        assert_eq!(replay, first);
        assert_eq!(first.events().len(), 2);
        assert_eq!(first.events()[0].event_id().as_uuid(), event_ids[0]);
        assert_eq!(first.events()[1].event_id().as_uuid(), event_ids[1]);
        assert_eq!(first.events()[0].workspace_id().as_uuid(), workspace_id);
        assert_eq!(first.events()[0].attempt_id().as_uuid(), attempt_id);
        assert_eq!(first.events()[0].entitlement_revision().get(), 1);
        assert_eq!(first.events()[0].consumed_compute().get(), 1_000);

        let second = exporter
            .list(export_request(AUTHORITY_A, first.next_cursor().clone(), 2))
            .await?;
        assert_eq!(second.events().len(), 1);
        assert_eq!(second.events()[0].event_id().as_uuid(), event_ids[2]);

        let empty = exporter
            .list(export_request(AUTHORITY_A, second.next_cursor().clone(), 2))
            .await?;
        assert!(empty.events().is_empty());
        assert_eq!(empty.next_cursor(), second.next_cursor());

        let appended_id = Uuid::new_v4();
        insert_usage(
            database.pool(),
            UsageFixture {
                authority_id: AUTHORITY_A,
                workspace_id,
                event_id: appended_id,
                attempt_id,
                start_ms: 1_786_500_103_000,
                end_ms: 1_786_500_104_000,
                consumed_ms: 1_000,
            },
        )
        .await?;
        let appended = exporter
            .list(export_request(AUTHORITY_A, empty.next_cursor().clone(), 2))
            .await?;
        assert_eq!(appended.events().len(), 1);
        assert_eq!(appended.events()[0].event_id().as_uuid(), appended_id);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn events_and_cursors_are_isolated_by_management_authority() -> TestResult {
    run_with_database(|database| async move {
        let workspace_a = provision_entitled_workspace(database.pool(), AUTHORITY_A).await?;
        let workspace_b = provision_entitled_workspace(database.pool(), AUTHORITY_B).await?;
        let event_a = Uuid::new_v4();
        let event_b = Uuid::new_v4();
        for (authority_id, workspace_id, event_id) in [
            (AUTHORITY_A, workspace_a, event_a),
            (AUTHORITY_B, workspace_b, event_b),
        ] {
            insert_usage(
                database.pool(),
                UsageFixture {
                    authority_id,
                    workspace_id,
                    event_id,
                    attempt_id: Uuid::new_v4(),
                    start_ms: 1_786_500_100_000,
                    end_ms: 1_786_500_101_000,
                    consumed_ms: 1_000,
                },
            )
            .await?;
        }

        let exporter = PostgresWorkspaceUsageExporter::new(database.pool().clone());
        let page_a = exporter
            .list(export_request(
                AUTHORITY_A,
                UsageExportCursor::beginning(),
                100,
            ))
            .await?;
        assert_eq!(page_a.events().len(), 1);
        assert_eq!(page_a.events()[0].event_id().as_uuid(), event_a);

        let crossed = exporter
            .list(export_request(
                AUTHORITY_B,
                page_a.next_cursor().clone(),
                100,
            ))
            .await
            .expect_err("another authority's cursor must be invalid");
        assert_eq!(crossed.kind(), UsageExportFailureKind::InvalidCursor);

        let malformed = exporter
            .list(export_request(
                AUTHORITY_A,
                UsageExportCursor::new(vec![1]).expect("bounded cursor"),
                100,
            ))
            .await
            .expect_err("malformed opaque cursor must fail");
        assert_eq!(malformed.kind(), UsageExportFailureKind::InvalidCursor);

        let unknown = exporter
            .list(export_request(
                AUTHORITY_A,
                UsageExportCursor::new(Uuid::new_v4().as_bytes().to_vec()).expect("bounded cursor"),
                100,
            ))
            .await
            .expect_err("unknown opaque cursor must fail");
        assert_eq!(unknown.kind(), UsageExportFailureKind::InvalidCursor);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn feed_constraints_reject_duplicate_intervals_and_wrong_bindings() -> TestResult {
    run_with_database(|database| async move {
        let workspace_id = provision_entitled_workspace(database.pool(), AUTHORITY_A).await?;
        let base = UsageFixture {
            authority_id: AUTHORITY_A,
            workspace_id,
            event_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            start_ms: 1_786_500_100_000,
            end_ms: 1_786_500_101_000,
            consumed_ms: 1_000,
        };
        insert_usage(database.pool(), base).await?;

        let duplicate = insert_usage(
            database.pool(),
            UsageFixture {
                event_id: Uuid::new_v4(),
                ..base
            },
        )
        .await
        .expect_err("the same accounted interval must be immutable");
        assert!(duplicate.as_database_error().is_some());

        let wrong_authority = insert_usage(
            database.pool(),
            UsageFixture {
                authority_id: AUTHORITY_B,
                event_id: Uuid::new_v4(),
                start_ms: base.end_ms,
                end_ms: base.end_ms + 1_000,
                ..base
            },
        )
        .await
        .expect_err("the event must match the workspace management binding");
        assert!(wrong_authority.as_database_error().is_some());
        Ok(())
    })
    .await
}
