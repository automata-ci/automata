use std::collections::BTreeSet;

use automata_ci_auth::{
    authorization::{AuthorizationContext, Permission},
    delegated_actor::{
        DelegatedActorAssertion, DelegatedActorRequestSnapshot,
        MAX_DELEGATED_TENANT_PERMISSION_CHECKS, ResolveDelegatedActorRequest,
    },
    human::{PrincipalId, TenantId},
    request_auth::ViewerDisplayMetadata,
    time::UnixTimestamp,
};
use uuid::Uuid;

#[test]
fn delegated_permission_requests_are_bounded_and_snapshots_fail_closed() {
    let tenant = TenantId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("tenant");
    let read = Permission::new("billing:read").expect("read permission");
    let manage = Permission::new("billing:manage").expect("manage permission");
    let request = ResolveDelegatedActorRequest::new(assertion(), tenant.clone())
        .with_tenant_permissions(BTreeSet::from([read.clone(), manage.clone()]))
        .expect("permission request");
    assert_eq!(
        request.requested_tenant_permissions(),
        &BTreeSet::from([read.clone(), manage.clone()])
    );

    let oversized = (0..=MAX_DELEGATED_TENANT_PERMISSION_CHECKS)
        .map(|index| Permission::new(format!("billing:test-{index}")).expect("permission"))
        .collect();
    assert!(
        ResolveDelegatedActorRequest::new(assertion(), tenant.clone())
            .with_tenant_permissions(oversized)
            .is_err()
    );

    let principal = PrincipalId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("principal");
    let authorization = AuthorizationContext::authenticated_at_revision(
        tenant.clone(),
        principal,
        BTreeSet::new(),
        7,
    )
    .expect("authorization");
    let snapshot = DelegatedActorRequestSnapshot::new(
        assertion(),
        &tenant,
        ViewerDisplayMetadata::new("Billing owner").expect("viewer"),
        authorization,
        BTreeSet::from([read.clone()]),
    )
    .expect("snapshot");
    assert!(snapshot.allows_tenant_permission(&read));
    assert!(!snapshot.allows_tenant_permission(&manage));
}

fn assertion() -> DelegatedActorAssertion {
    DelegatedActorAssertion::new(
        "https://cloud.automata.example",
        Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("subject"),
        Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("session"),
        Uuid::parse_str("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").expect("assertion"),
        UnixTimestamp::from_seconds(100),
        UnixTimestamp::from_seconds(110),
        UnixTimestamp::from_seconds(230),
    )
    .expect("delegated assertion")
}
