use automata_ci_core::{UnixMillis, WorkflowId};
use automata_ci_store::{
    RepositoryId, SetWorkflowEnableState, TenantScope, WorkflowEnableState,
    WorkflowEnableStateRecord, WorkflowEnableStateRevision, WorkflowEnableStateValueError,
};
use uuid::Uuid;

fn record(revision: u64, state: WorkflowEnableState) -> WorkflowEnableStateRecord {
    WorkflowEnableStateRecord::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        RepositoryId::from_uuid(Uuid::from_u128(1)),
        WorkflowId::from_uuid(Uuid::from_u128(2)),
        ".ci/workflows/build.yml",
        WorkflowEnableStateRevision::new(revision).expect("revision"),
        state,
        UnixMillis::new(i64::try_from(revision).expect("time")),
    )
    .expect("state record")
}

#[test]
fn state_history_requires_a_contiguous_compare_and_set_revision() {
    let first = SetWorkflowEnableState::new(record(1, WorkflowEnableState::Enabled), None)
        .expect("initial revision");
    assert_eq!(first.next().state(), WorkflowEnableState::Enabled);
    let next = SetWorkflowEnableState::new(
        record(2, WorkflowEnableState::Disabled),
        Some(WorkflowEnableStateRevision::new(1).expect("revision")),
    )
    .expect("successor revision");
    assert_eq!(next.next().state(), WorkflowEnableState::Disabled);

    assert_eq!(
        SetWorkflowEnableState::new(
            record(3, WorkflowEnableState::Enabled),
            Some(WorkflowEnableStateRevision::new(1).expect("revision")),
        ),
        Err(WorkflowEnableStateValueError::NonContiguousRevision)
    );
}

#[test]
fn state_identity_rejects_traversing_and_noncanonical_paths() {
    for path in [
        "",
        "/build.yml",
        "../build.yml",
        "a//build.yml",
        "a\\build.yml",
    ] {
        assert_eq!(
            WorkflowEnableStateRecord::new(
                TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
                RepositoryId::from_uuid(Uuid::from_u128(1)),
                WorkflowId::from_uuid(Uuid::from_u128(2)),
                path,
                WorkflowEnableStateRevision::new(1).expect("revision"),
                WorkflowEnableState::Enabled,
                UnixMillis::new(1),
            ),
            Err(WorkflowEnableStateValueError::InvalidWorkflowPath)
        );
    }
}

#[test]
fn durable_state_names_are_closed_and_stable() {
    assert_eq!(WorkflowEnableState::Enabled.as_durable_str(), "enabled");
    assert_eq!(WorkflowEnableState::Disabled.as_durable_str(), "disabled");
}
