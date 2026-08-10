use std::collections::BTreeSet;

use automata_ci_auth::{
    authorization::{
        AuthorizationScope, Permission, RepositoryResource, RepositoryResourceId, RoleName,
        RunnerGroupResourceId,
    },
    human::{PrincipalId, TenantId},
    management::{
        ChangeMemberStatus, CreateRole, DirectBindingGrantOptions, DirectBindingPrincipalOption,
        DirectBindingRepositoryOption, DirectBindingRoleOption, DirectBindingRunnerGroupOption,
        GrantRole, HumanRbacManagementRepository, ListManagementRoleBindings, ManagedPrincipalId,
        ManagementActor, ManagementMutationCapabilities, ManagementPage, ManagementPageSize,
        ManagementRequestId, ManagementRevision, ManagementRoleBindingCursor, ManagementValueError,
        MemberRecord, MemberStatus, ProviderRoleMappingId, ReadDirectBindingGrantOptions,
        ReadManagementMutationCapabilities, RoleBindingId, RoleDetailRecord, RoleId, RoleKind,
        RolePermissionRecord, RoleRecord,
    },
    session::SessionId,
    time::UnixTimestamp,
};
use static_assertions::assert_obj_safe;
use uuid::Uuid;

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).expect("tenant")
}

fn principal(value: &str) -> PrincipalId {
    PrincipalId::new(value).expect("principal")
}

fn managed_principal(value: &str) -> ManagedPrincipalId {
    ManagedPrincipalId::new(value).expect("managed principal")
}

fn actor() -> ManagementActor {
    ManagementActor::new(
        tenant("tenant-a"),
        principal("550e8400-e29b-41d4-a716-446655440000"),
        SessionId::new("550e8400-e29b-41d4-a716-446655440001").expect("session"),
        ManagementRevision::new(7).expect("revision"),
        Some(ManagementRequestId::new("request-7").expect("request ID")),
        UnixTimestamp::from_seconds(1_000),
    )
}

#[test]
fn identifiers_require_canonical_non_nil_uuids() {
    for invalid in [
        "00000000-0000-0000-0000-000000000000",
        "550E8400-E29B-41D4-A716-446655440002",
        "550e8400e29b41d4a716446655440002",
        "not-a-uuid",
    ] {
        assert_eq!(
            RoleId::new(invalid),
            Err(ManagementValueError::InvalidRoleId)
        );
        assert_eq!(
            RoleBindingId::new(invalid),
            Err(ManagementValueError::InvalidRoleBindingId)
        );
        assert_eq!(
            ManagedPrincipalId::new(invalid),
            Err(ManagementValueError::InvalidPrincipalId)
        );
    }

    let valid = "550e8400-e29b-41d4-a716-446655440002";
    assert_eq!(RoleId::new(valid).expect("role").to_string(), valid);
}

#[test]
fn revisions_pages_and_audit_request_ids_are_bounded() {
    assert_eq!(
        ManagementRevision::new(0),
        Err(ManagementValueError::InvalidRevision)
    );
    assert_eq!(
        ManagementPageSize::new(0),
        Err(ManagementValueError::InvalidPageSize)
    );
    assert_eq!(
        ManagementPageSize::new(101),
        Err(ManagementValueError::InvalidPageSize)
    );
    assert_eq!(
        ManagementRequestId::new("contains whitespace"),
        Err(ManagementValueError::InvalidRequestId)
    );

    let result = ManagementPage::new(vec![1, 2], None, ManagementPageSize::new(1).unwrap());
    assert_eq!(result, Err(ManagementValueError::OversizedPage));

    let page = ManagementPage::new_authorized(
        vec![1],
        None,
        ManagementPageSize::new(1).unwrap(),
        ManagementRevision::new(17).unwrap(),
    )
    .expect("authorized page");
    assert_eq!(
        page.mutation_authorization_revision(),
        Some(ManagementRevision::new(17).unwrap())
    );
}

#[test]
fn role_records_reject_mutable_built_ins_and_bad_display_text() {
    let role_id = RoleId::from_uuid(Uuid::new_v4()).expect("role ID");
    let role_name = RoleName::new("operator").expect("role name");
    assert_eq!(
        RoleRecord::new(
            role_id,
            role_name.clone(),
            "Operator",
            RoleKind::BuiltIn,
            false,
            ManagementRevision::new(1).unwrap(),
            BTreeSet::new(),
        ),
        Err(ManagementValueError::InvalidRoleKind)
    );
    for invalid in [
        "bad\nname".to_owned(),
        " \u{200b}".to_owned(),
        "\u{200b}".to_owned(),
        "review\u{202e}role".to_owned(),
        "🚀".repeat(64),
    ] {
        assert_eq!(
            CreateRole::new(actor(), role_id, role_name.clone(), invalid),
            Err(ManagementValueError::InvalidDisplayName)
        );
    }
    assert!(CreateRole::new(actor(), role_id, role_name, "🚀".repeat(63)).is_ok());
}

#[test]
fn member_projection_has_stable_uuid_and_bounded_provider_metadata() {
    let revision = ManagementRevision::new(1).unwrap();
    for invalid in [
        "bad\nlogin".to_owned(),
        " \u{200b}".to_owned(),
        "\u{200b}".to_owned(),
        "review\u{202e}login".to_owned(),
        "🚀".repeat(64),
    ] {
        let provider = automata_ci_auth::human::ProviderId::new("github").unwrap();
        assert_eq!(
            MemberRecord::new(
                managed_principal("550e8400-e29b-41d4-a716-446655440003"),
                provider,
                invalid,
                None,
                MemberStatus::Active,
                revision,
                revision,
            ),
            Err(ManagementValueError::InvalidProviderLogin)
        );
    }
    assert!(
        MemberRecord::new(
            managed_principal("550e8400-e29b-41d4-a716-446655440003"),
            automata_ci_auth::human::ProviderId::new("github").unwrap(),
            "🚀".repeat(63),
            None,
            MemberStatus::Active,
            revision,
            revision,
        )
        .is_ok()
    );
}

#[test]
fn direct_role_grants_reject_cross_tenant_and_expired_scope() {
    let repository = RepositoryResource::new(
        tenant("tenant-b"),
        RepositoryResourceId::from_uuid(Uuid::new_v4()).expect("repository"),
    );
    let role_id = RoleId::from_uuid(Uuid::new_v4()).expect("role");
    let binding_id = RoleBindingId::from_uuid(Uuid::new_v4()).expect("binding");
    let target = managed_principal("550e8400-e29b-41d4-a716-446655440003");

    assert_eq!(
        GrantRole::new(
            actor(),
            binding_id,
            target,
            role_id,
            AuthorizationScope::repository(repository),
            None,
        ),
        Err(ManagementValueError::CrossTenantScope)
    );
    assert_eq!(
        GrantRole::new(
            actor(),
            binding_id,
            target,
            role_id,
            AuthorizationScope::tenant(tenant("tenant-a")),
            Some(UnixTimestamp::from_seconds(1_000)),
        ),
        Err(ManagementValueError::InvalidBindingLifetime)
    );
}

#[test]
fn suspension_requires_a_reason_and_restore_forbids_one() {
    let target = managed_principal("550e8400-e29b-41d4-a716-446655440003");
    let revision = ManagementRevision::new(1).unwrap();
    assert_eq!(
        ChangeMemberStatus::new(actor(), target, revision, MemberStatus::Suspended, None),
        Err(ManagementValueError::InvalidMemberStatusReason)
    );
    assert_eq!(
        ChangeMemberStatus::new(
            actor(),
            target,
            revision,
            MemberStatus::Active,
            Some("not allowed".to_owned()),
        ),
        Err(ManagementValueError::InvalidMemberStatusReason)
    );
    for invalid in [
        "bad\nreason".to_owned(),
        " \u{200b}".to_owned(),
        "\u{200b}".to_owned(),
        "review\u{202e}reason".to_owned(),
        "🚀".repeat(257),
    ] {
        assert_eq!(
            ChangeMemberStatus::new(
                actor(),
                target,
                revision,
                MemberStatus::Suspended,
                Some(invalid),
            ),
            Err(ManagementValueError::InvalidReason)
        );
    }
    assert!(
        ChangeMemberStatus::new(
            actor(),
            target,
            revision,
            MemberStatus::Suspended,
            Some("🚀".repeat(256)),
        )
        .is_ok()
    );
}

#[test]
fn permission_descriptions_follow_the_safe_display_contract() {
    let permission = Permission::new("runs:read").expect("permission");
    for invalid in [
        " \u{200b}",
        "\u{200b}",
        "review\u{202e}runs",
        "bad\ndescription",
    ] {
        assert_eq!(
            RolePermissionRecord::new(permission.clone(), invalid, false, false),
            Err(ManagementValueError::InvalidPermissionDescription)
        );
    }
    assert!(
        RolePermissionRecord::new(permission, "Review workflow run metadata", false, false,)
            .is_ok()
    );
}

#[test]
fn debug_surfaces_contain_no_authority_claims_or_secret_fields() {
    let rendered = format!("{:?}", actor());
    assert!(rendered.contains("authorization_revision"));
    assert!(!rendered.contains("roles"));
    assert!(!rendered.contains("permissions"));
    assert!(!rendered.contains("token"));
}

#[test]
fn permission_values_remain_exact_and_non_wildcard() {
    assert!(Permission::new("roles:manage").is_ok());
    assert!(Permission::new("roles:*").is_err());
}

#[test]
fn rich_binding_cursors_are_canonical_and_provider_ids_are_stable() {
    let principal = managed_principal("550e8400-e29b-41d4-a716-446655440003");
    let mapping =
        ProviderRoleMappingId::new("550e8400-e29b-41d4-a716-446655440004").expect("mapping");
    let derived = RoleBindingId::for_provider_observation(principal, mapping);
    assert_eq!(
        derived,
        RoleBindingId::for_provider_observation(principal, mapping)
    );
    assert_ne!(
        derived,
        RoleBindingId::for_provider_observation(
            managed_principal("550e8400-e29b-41d4-a716-446655440005"),
            mapping,
        )
    );

    let encoded = ManagementRoleBindingCursor::ProviderObserved {
        principal_id: principal,
        mapping_id: mapping,
    }
    .encode();
    assert_eq!(
        ManagementRoleBindingCursor::new(&encoded).expect("cursor"),
        ManagementRoleBindingCursor::ProviderObserved {
            principal_id: principal,
            mapping_id: mapping,
        }
    );
    assert_eq!(
        ManagementRoleBindingCursor::new(format!("{encoded}:extra")),
        Err(ManagementValueError::InvalidCursor)
    );
    assert_eq!(
        ListManagementRoleBindings::new(
            actor(),
            Some(encoded.as_str()),
            ManagementPageSize::new(10).unwrap(),
            Some(managed_principal("550e8400-e29b-41d4-a716-446655440005")),
        ),
        Err(ManagementValueError::InvalidCursor)
    );
}

#[test]
fn role_detail_requires_the_full_ordered_grant_consistent_catalog() {
    let role_id = RoleId::from_uuid(Uuid::new_v4()).expect("role ID");
    let granted = Permission::new("runs:read").expect("permission");
    let role = RoleRecord::new(
        role_id,
        RoleName::new("reader").expect("role name"),
        "Reader",
        RoleKind::Custom,
        false,
        ManagementRevision::new(1).unwrap(),
        BTreeSet::from([granted.clone()]),
    )
    .expect("role");
    let catalog = vec![
        RolePermissionRecord::new(
            Permission::new("jobs:read").expect("permission"),
            "Read jobs.",
            false,
            false,
        )
        .expect("catalog entry"),
        RolePermissionRecord::new(granted, "Read runs.", false, true).expect("catalog entry"),
    ];
    assert!(RoleDetailRecord::new(role.clone(), catalog).is_ok());
    assert_eq!(
        RoleDetailRecord::new(
            role,
            vec![
                RolePermissionRecord::new(
                    Permission::new("runs:read").unwrap(),
                    "Read runs.",
                    false,
                    false,
                )
                .unwrap()
            ],
        ),
        Err(ManagementValueError::InvalidPermissionCatalog)
    );
}

#[test]
fn mutation_capabilities_are_revision_bound_and_requests_are_redacted() {
    let capabilities = ManagementMutationCapabilities::new(
        ManagementRevision::new(19).unwrap(),
        true,
        false,
        true,
    );
    assert_eq!(
        capabilities.authorization_revision(),
        ManagementRevision::new(19).unwrap()
    );
    assert!(capabilities.members_manage());
    assert!(!capabilities.roles_manage());
    assert!(capabilities.role_bindings_manage());

    let capability_debug = format!("{:?}", ReadManagementMutationCapabilities::new(actor()));
    let grant_debug = format!("{:?}", ReadDirectBindingGrantOptions::new(actor()));
    for rendered in [capability_debug, grant_debug] {
        assert!(!rendered.contains("tenant-a"));
        assert!(!rendered.contains("request-7"));
        assert!(!rendered.contains("550e8400"));
    }
}

#[test]
fn direct_binding_grant_options_are_complete_ordered_and_debug_redacted() {
    let revision = ManagementRevision::new(23).unwrap();
    let principal_a = DirectBindingPrincipalOption::new(
        ManagedPrincipalId::from_uuid(Uuid::from_u128(1)).unwrap(),
        "Alpha member",
    )
    .unwrap();
    let principal_b = DirectBindingPrincipalOption::new(
        ManagedPrincipalId::from_uuid(Uuid::from_u128(2)).unwrap(),
        "Beta member",
    )
    .unwrap();
    let role = DirectBindingRoleOption::new(
        RoleId::from_uuid(Uuid::from_u128(3)).unwrap(),
        RoleName::new("reader").unwrap(),
        "Reader",
        RoleKind::Custom,
        false,
    )
    .unwrap();
    let repository = DirectBindingRepositoryOption::new(
        RepositoryResourceId::from_uuid(Uuid::from_u128(4)).unwrap(),
        "acme/widgets",
    )
    .unwrap();
    let runner_group = DirectBindingRunnerGroupOption::new(
        RunnerGroupResourceId::from_uuid(Uuid::from_u128(5)).unwrap(),
        "trusted-linux",
    )
    .unwrap();
    let options = DirectBindingGrantOptions::new(
        revision,
        vec![principal_a.clone(), principal_b.clone()],
        vec![role],
        vec![repository],
        vec![runner_group],
    )
    .expect("canonical options");
    assert_eq!(options.authorization_revision(), revision);
    assert_eq!(options.principals()[0].display_name(), "Alpha member");
    assert_eq!(options.roles()[0].display_name(), "Reader");
    assert_eq!(options.repositories()[0].display_name(), "acme/widgets");
    assert_eq!(options.runner_groups()[0].display_name(), "trusted-linux");
    let rendered = format!("{options:?}");
    for private_label in [
        "Alpha member",
        "Beta member",
        "Reader",
        "acme/widgets",
        "trusted-linux",
    ] {
        assert!(!rendered.contains(private_label));
    }

    assert_eq!(
        DirectBindingGrantOptions::new(
            revision,
            vec![principal_b, principal_a],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
        Err(ManagementValueError::InvalidGrantOptionOrder)
    );
    let oversized = (1_u128..=501)
        .map(|number| {
            DirectBindingPrincipalOption::new(
                ManagedPrincipalId::from_uuid(Uuid::from_u128(number)).unwrap(),
                "same label",
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        DirectBindingGrantOptions::new(revision, oversized, Vec::new(), Vec::new(), Vec::new(),),
        Err(ManagementValueError::OversizedGrantOptions)
    );
}

assert_obj_safe!(HumanRbacManagementRepository);
