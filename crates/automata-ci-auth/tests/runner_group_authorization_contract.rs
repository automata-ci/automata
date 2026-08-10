use std::collections::{BTreeMap, BTreeSet};

use automata_ci_auth::{
    authorization::{
        AuthorizationContext, AuthorizationRequest, AuthorizationScope,
        CompositeAuthorizationPolicy, Permission, RbacPolicy, RepositoryResource,
        RepositoryResourceId, RoleName, RunnerGroupResource, RunnerGroupResourceId,
        ScopedRoleGrant,
    },
    human::{PrincipalId, TenantId},
};

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).expect("valid tenant")
}

fn role(value: &str) -> RoleName {
    RoleName::new(value).expect("valid role")
}

fn permission(value: &str) -> Permission {
    Permission::new(value).expect("valid permission")
}

fn runner_group(tenant_id: &str, id: &str) -> RunnerGroupResource {
    RunnerGroupResource::new(
        tenant(tenant_id),
        RunnerGroupResourceId::new(id).expect("valid runner-group resource ID"),
    )
}

fn repository(tenant_id: &str, id: &str) -> RepositoryResource {
    RepositoryResource::new(
        tenant(tenant_id),
        RepositoryResourceId::new(id).expect("valid repository resource ID"),
    )
}

fn context(grants: impl IntoIterator<Item = ScopedRoleGrant>) -> AuthorizationContext {
    AuthorizationContext::authenticated(
        tenant("tenant-a"),
        PrincipalId::new("principal-a").expect("valid principal"),
        grants.into_iter().collect(),
    )
    .expect("same-tenant grants")
}

fn policy() -> CompositeAuthorizationPolicy {
    let operator = role("runner-operator");
    CompositeAuthorizationPolicy::new(
        RbacPolicy::new(BTreeMap::from([(
            operator,
            BTreeSet::from([permission("runners:manage")]),
        )])),
        BTreeMap::new(),
    )
}

#[test]
fn runner_group_identity_is_canonical_non_nil_uuid() {
    assert!(RunnerGroupResourceId::new("not-a-uuid").is_err());
    assert!(RunnerGroupResourceId::new("00000000-0000-0000-0000-000000000000").is_err());
    assert!(RunnerGroupResourceId::new("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA").is_err());

    let id =
        RunnerGroupResourceId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("canonical UUID");
    let encoded = serde_json::to_string(&id).expect("serialize");
    let decoded: RunnerGroupResourceId = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, id);
}

#[test]
fn runner_group_grant_applies_only_to_exact_group() {
    let group_a = runner_group("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let group_b = runner_group("tenant-a", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    let operator = role("runner-operator");
    let context = context([ScopedRoleGrant::new(
        AuthorizationScope::runner_group(group_a.clone()),
        operator,
    )]);
    let policy = policy();

    assert!(policy.allows(
        &context,
        &AuthorizationRequest::new(
            AuthorizationScope::runner_group(group_a),
            permission("runners:manage"),
        ),
    ));
    assert!(!policy.allows(
        &context,
        &AuthorizationRequest::new(
            AuthorizationScope::runner_group(group_b),
            permission("runners:manage"),
        ),
    ));
}

#[test]
fn runner_group_grant_never_widens_to_tenant_or_repository() {
    let group = runner_group("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let operator = role("runner-operator");
    let context = context([ScopedRoleGrant::new(
        AuthorizationScope::runner_group(group),
        operator,
    )]);
    let policy = policy();

    assert!(!policy.allows(
        &context,
        &AuthorizationRequest::new(
            AuthorizationScope::tenant(tenant("tenant-a")),
            permission("runners:manage"),
        ),
    ));
    assert!(!policy.allows(
        &context,
        &AuthorizationRequest::new(
            AuthorizationScope::repository(repository(
                "tenant-a",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            )),
            permission("runners:manage"),
        ),
    ));
}

#[test]
fn tenant_grant_still_contains_runner_groups_only_in_same_tenant() {
    let operator = role("runner-operator");
    let context = context([ScopedRoleGrant::new(
        AuthorizationScope::tenant(tenant("tenant-a")),
        operator,
    )]);
    let policy = policy();

    assert!(policy.allows(
        &context,
        &AuthorizationRequest::new(
            AuthorizationScope::runner_group(runner_group(
                "tenant-a",
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            )),
            permission("runners:manage"),
        ),
    ));
    assert!(!policy.allows(
        &context,
        &AuthorizationRequest::new(
            AuthorizationScope::runner_group(runner_group(
                "tenant-b",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            )),
            permission("runners:manage"),
        ),
    ));
}
