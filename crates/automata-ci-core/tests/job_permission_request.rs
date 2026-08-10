use automata_ci_core::{JobPermissionGrant, JobPermissionRequest, PermissionLevel};

#[test]
fn permission_lookup_is_total_and_fails_closed_for_invalid_mappings() {
    assert_eq!(
        JobPermissionRequest::ProviderDefault.requested_level("id-token"),
        None
    );
    assert_eq!(
        JobPermissionRequest::ReadAll.requested_level("id-token"),
        Some(PermissionLevel::Read)
    );
    assert_eq!(
        JobPermissionRequest::WriteAll.requested_level("id-token"),
        Some(PermissionLevel::Write)
    );

    let mapping = JobPermissionRequest::mapping([
        JobPermissionGrant::new("contents", PermissionLevel::Read),
        JobPermissionGrant::new("id-token", PermissionLevel::Write),
    ]);
    assert_eq!(
        mapping.requested_level("id-token"),
        Some(PermissionLevel::Write)
    );
    assert_eq!(mapping.requested_level("statuses"), None);

    let denied =
        JobPermissionRequest::mapping([JobPermissionGrant::new("id-token", PermissionLevel::None)]);
    assert_eq!(
        denied.requested_level("id-token"),
        Some(PermissionLevel::None)
    );

    let invalid = JobPermissionRequest::Mapping(vec![
        JobPermissionGrant::new("id-token", PermissionLevel::Write),
        JobPermissionGrant::new("contents", PermissionLevel::Read),
    ]);
    assert_eq!(invalid.requested_level("id-token"), None);
}
