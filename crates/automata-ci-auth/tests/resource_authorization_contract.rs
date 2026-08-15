#[path = "resource_authorization_contract/output_policy_contract.rs"]
mod output_policy_contract;

use std::collections::{BTreeMap, BTreeSet};

use automata_ci_auth::{
    authorization::{
        AuthorizationContext, AuthorizationContextError, AuthorizationRequest, AuthorizationScope,
        CompositeAuthorizationPolicy, OutputVisibility, Permission, RbacPolicy,
        RepositoryPublicationPolicy, RepositoryResource, RepositoryResourceId, RoleName,
        ScopedRoleGrant, SecretExposureClass,
    },
    human::{PrincipalId, TenantId},
};
use serde_json::json;

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).expect("valid tenant")
}

fn principal(value: &str) -> PrincipalId {
    PrincipalId::new(value).expect("valid principal")
}

fn role(value: &str) -> RoleName {
    RoleName::new(value).expect("valid role")
}

fn permission(value: &str) -> Permission {
    Permission::new(value).expect("valid permission")
}

fn repository(tenant_id: &str, repository_id: &str) -> RepositoryResource {
    RepositoryResource::new(
        tenant(tenant_id),
        RepositoryResourceId::new(repository_id).expect("valid repository resource ID"),
    )
}

fn authenticated(
    tenant_id: &str,
    grants: impl IntoIterator<Item = ScopedRoleGrant>,
) -> AuthorizationContext {
    AuthorizationContext::authenticated(
        tenant(tenant_id),
        principal("principal-1"),
        grants.into_iter().collect(),
    )
    .expect("valid authorization context")
}

fn request(repository: RepositoryResource, permission_name: &str) -> AuthorizationRequest {
    AuthorizationRequest::new(
        AuthorizationScope::repository(repository),
        permission(permission_name),
    )
}

fn safe_request(repository: RepositoryResource, permission_name: &str) -> AuthorizationRequest {
    request(repository, permission_name).with_secret_exposure(SecretExposureClass::Secretless)
}

#[test]
fn resource_authorization_is_default_deny() {
    let repository = repository("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let request = request(repository, "runs:read");
    let policy = CompositeAuthorizationPolicy::default();

    assert!(!policy.allows(&AuthorizationContext::anonymous(), &request));
    assert!(!policy.allows(&authenticated("tenant-a", []), &request));
}

#[test]
fn privileged_role_names_have_no_scoped_bypass() {
    let repository = repository("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let administrator = role("administrator");
    let context = authenticated(
        "tenant-a",
        [ScopedRoleGrant::new(
            AuthorizationScope::repository(repository.clone()),
            administrator,
        )],
    );
    let policy = CompositeAuthorizationPolicy::default();

    assert!(!policy.allows(&context, &request(repository, "runs:cancel")));
}

#[test]
fn role_grants_apply_only_to_their_exact_scope() {
    let repository_a = repository("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let repository_b = repository("tenant-a", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    let repository_other_tenant = repository("tenant-b", "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    let viewer = role("viewer");
    let policy = CompositeAuthorizationPolicy::new(
        RbacPolicy::new(BTreeMap::from([(
            viewer.clone(),
            BTreeSet::from([permission("runs:read")]),
        )])),
        BTreeMap::new(),
    );
    let context = authenticated(
        "tenant-a",
        [ScopedRoleGrant::new(
            AuthorizationScope::repository(repository_a.clone()),
            viewer,
        )],
    );

    assert!(policy.allows(&context, &request(repository_a, "runs:read")));
    assert!(!policy.allows(&context, &request(repository_b, "runs:read")));
    assert!(!policy.allows(&context, &request(repository_other_tenant, "runs:read")));
}

#[test]
fn tenant_grants_cover_only_resources_in_that_tenant() {
    let viewer = role("viewer");
    let policy = CompositeAuthorizationPolicy::new(
        RbacPolicy::new(BTreeMap::from([(
            viewer.clone(),
            BTreeSet::from([permission("repositories:read")]),
        )])),
        BTreeMap::new(),
    );
    let context = authenticated(
        "tenant-a",
        [ScopedRoleGrant::new(
            AuthorizationScope::tenant(tenant("tenant-a")),
            viewer,
        )],
    );

    assert!(policy.allows(
        &context,
        &request(
            repository("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            "repositories:read",
        ),
    ));
    assert!(!policy.allows(
        &context,
        &request(
            repository("tenant-b", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            "repositories:read",
        ),
    ));
}

#[test]
fn cross_tenant_role_grants_cannot_enter_a_context() {
    let result = AuthorizationContext::authenticated(
        tenant("tenant-a"),
        principal("principal-1"),
        BTreeSet::from([ScopedRoleGrant::new(
            AuthorizationScope::tenant(tenant("tenant-b")),
            role("viewer"),
        )]),
    );

    assert_eq!(result, Err(AuthorizationContextError::CrossTenantRoleGrant));
}

#[test]
fn session_resolved_context_retains_one_positive_authorization_revision() {
    let context = AuthorizationContext::authenticated_at_revision(
        tenant("tenant-a"),
        principal("principal-1"),
        BTreeSet::new(),
        7,
    )
    .expect("positive durable revision");
    assert_eq!(context.authorization_revision(), Some(7));

    assert_eq!(
        AuthorizationContext::authenticated_at_revision(
            tenant("tenant-a"),
            principal("principal-1"),
            BTreeSet::new(),
            0,
        ),
        Err(AuthorizationContextError::InvalidAuthorizationRevision)
    );
    assert_eq!(
        authenticated("tenant-a", []).authorization_revision(),
        None,
        "trusted in-process fixtures remain distinguishable from session evidence"
    );
}

#[test]
fn repository_resource_identity_is_canonical_and_validated_on_decode() {
    assert!(RepositoryResourceId::new("not-a-uuid").is_err());
    assert!(RepositoryResourceId::new("00000000-0000-0000-0000-000000000000").is_err());
    assert!(RepositoryResourceId::new("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA").is_err());

    let encoded = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let decoded: RepositoryResourceId =
        serde_json::from_value(encoded.clone()).expect("canonical UUID");
    assert_eq!(serde_json::to_value(decoded).expect("serialize"), encoded);
    assert!(
        serde_json::from_value::<RepositoryResourceId>(json!(
            "00000000-0000-0000-0000-000000000000"
        ))
        .is_err()
    );
}

#[test]
fn public_surfaces_grant_only_the_configured_read_permissions() {
    let published = repository("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let private = repository("tenant-a", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    let policy = CompositeAuthorizationPolicy::new(
        RbacPolicy::default(),
        BTreeMap::from([(
            published.clone(),
            RepositoryPublicationPolicy::new(
                OutputVisibility::Public,
                OutputVisibility::Public,
                OutputVisibility::Public,
            ),
        )]),
    );
    let anonymous = AuthorizationContext::anonymous();

    for read_permission in [
        "repositories:read",
        "workflows:read",
        "runs:read",
        "jobs:read",
        "logs:read",
        "artifacts:read",
        "artifacts:download",
    ] {
        assert!(
            policy.allows(
                &anonymous,
                &safe_request(published.clone(), read_permission)
            ),
            "{read_permission} should be public"
        );
    }

    for mutation_or_private_permission in [
        "repositories:update",
        "runs:dispatch",
        "runs:cancel",
        "artifacts:delete",
        "secrets:metadata:read",
        "secrets:update",
    ] {
        assert!(
            !policy.allows(
                &anonymous,
                &request(published.clone(), mutation_or_private_permission)
            ),
            "{mutation_or_private_permission} must never be published"
        );
    }

    assert!(!policy.allows(&anonymous, &request(private, "repositories:read")));
}

#[test]
fn dashboard_logs_and_artifacts_are_independently_configurable() {
    let repository = repository("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let policy = CompositeAuthorizationPolicy::new(
        RbacPolicy::default(),
        BTreeMap::from([(
            repository.clone(),
            RepositoryPublicationPolicy::new(
                OutputVisibility::Public,
                OutputVisibility::Authenticated,
                OutputVisibility::Private,
            ),
        )]),
    );
    let anonymous = AuthorizationContext::anonymous();
    let signed_in = authenticated("tenant-a", []);

    assert!(policy.allows(&anonymous, &request(repository.clone(), "runs:read")));
    assert!(!policy.allows(&anonymous, &safe_request(repository.clone(), "logs:read")));
    assert!(policy.allows(&signed_in, &safe_request(repository.clone(), "logs:read")));
    assert!(!policy.allows(
        &anonymous,
        &request(repository.clone(), "artifacts:download")
    ));
    assert!(!policy.allows(&signed_in, &request(repository, "artifacts:download")));
}

#[test]
fn public_logs_and_artifacts_require_trusted_secret_safe_evidence() {
    let repository = repository("tenant-a", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let policy = CompositeAuthorizationPolicy::new(
        RbacPolicy::default(),
        BTreeMap::from([(
            repository.clone(),
            RepositoryPublicationPolicy::new(
                OutputVisibility::Public,
                OutputVisibility::Public,
                OutputVisibility::Public,
            ),
        )]),
    );
    let anonymous = AuthorizationContext::anonymous();

    assert!(policy.allows(&anonymous, &request(repository.clone(), "runs:read")));
    assert!(!policy.allows(&anonymous, &request(repository.clone(), "logs:read")));
    assert!(!policy.allows(
        &anonymous,
        &request(repository.clone(), "artifacts:download")
    ));
    assert!(policy.allows(&anonymous, &safe_request(repository.clone(), "logs:read")));
    assert!(policy.allows(
        &anonymous,
        &safe_request(repository.clone(), "artifacts:download")
    ));
    assert!(!policy.allows(&anonymous, &safe_request(repository, "artifacts:delete")));
}
