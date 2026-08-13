use automata_ci_auth::{
    authorization::{AuthorizationScope, RoleName},
    github_mapping_management::{
        CreateGithubMapping, GITHUB_MAPPING_OPTION_LIMIT, GithubMappingCursor,
        GithubMappingManagementRepository, GithubMappingOptions, GithubMappingPage,
        GithubMappingPageSize, GithubMappingRecord, GithubMappingStatus, GithubMappingValueError,
        ListGithubMappings, ManagedGithubMappingSource,
    },
    human::{PrincipalId, TenantId},
    management::{
        DirectBindingRoleOption, ManagementActor, ManagementRequestId, ManagementRevision,
        ProviderRoleMappingId, RoleId, RoleKind,
    },
    session::SessionId,
    time::UnixTimestamp,
};
use static_assertions::assert_impl_all;
use uuid::Uuid;

fn mapping_id(value: u128) -> ProviderRoleMappingId {
    ProviderRoleMappingId::from_uuid(Uuid::from_u128(value)).expect("mapping ID")
}

fn role_id(value: u128) -> RoleId {
    RoleId::from_uuid(Uuid::from_u128(value)).expect("role ID")
}

fn revision(value: u64) -> ManagementRevision {
    ManagementRevision::new(value).expect("revision")
}

fn actor(tenant_id: &str) -> ManagementActor {
    ManagementActor::new(
        TenantId::new(tenant_id).expect("tenant"),
        PrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("principal"),
        SessionId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("session"),
        revision(7),
        Some(ManagementRequestId::new("mapping-request").expect("request ID")),
        UnixTimestamp::from_seconds(100),
    )
}

fn record(value: u128) -> GithubMappingRecord {
    GithubMappingRecord::new(
        mapping_id(value),
        ManagedGithubMappingSource::organization(42, "automata-ci").expect("source"),
        role_id(90),
        AuthorizationScope::tenant(TenantId::new("tenant-a").expect("tenant")),
        GithubMappingStatus::Active,
        revision(1),
    )
}

#[test]
fn page_size_and_uuid_cursor_are_current_only_and_bounded() {
    assert_eq!(GithubMappingPageSize::default().value(), 50);
    assert_eq!(GithubMappingPageSize::new(1).expect("minimum").value(), 1);
    assert_eq!(
        GithubMappingPageSize::new(100).expect("maximum").value(),
        100
    );
    assert_eq!(
        GithubMappingPageSize::new(0),
        Err(GithubMappingValueError::InvalidPageSize)
    );
    assert_eq!(
        GithubMappingPageSize::new(101),
        Err(GithubMappingValueError::InvalidPageSize)
    );

    let exact = "00000000-0000-4000-8000-000000000001";
    assert_eq!(
        GithubMappingCursor::new(exact).expect("cursor").encode(),
        exact
    );
    for invalid in [
        "",
        "00000000-0000-0000-0000-000000000000",
        "00000000000040008000000000000001",
        "00000000-0000-4000-8000-000000000001 ",
    ] {
        assert_eq!(
            GithubMappingCursor::new(invalid),
            Err(GithubMappingValueError::InvalidCursor)
        );
    }

    let request = ListGithubMappings::new(actor("tenant-a"), None, None).expect("request");
    assert_eq!(request.limit().value(), 50);
}

#[test]
fn numeric_sources_accept_exact_bigint_and_reject_zero_or_overflow() {
    let maximum = u64::try_from(i64::MAX).expect("maximum");
    let organization =
        ManagedGithubMappingSource::organization(maximum, "Automata-CI").expect("maximum ID");
    assert_eq!(organization.organization_id().get(), i64::MAX);
    assert_eq!(organization.organization_login(), "automata-ci");
    assert_eq!(organization.team_id(), None);

    let team = ManagedGithubMappingSource::team(maximum, "Automata-CI", maximum, "Core_Team")
        .expect("maximum team");
    assert_eq!(team.organization_id().get(), i64::MAX);
    assert_eq!(team.team_id().expect("team").get(), i64::MAX);
    assert_eq!(team.team_slug(), Some("core_team"));

    for value in [0, maximum + 1] {
        assert_eq!(
            ManagedGithubMappingSource::organization(value, "automata-ci"),
            Err(GithubMappingValueError::InvalidGithubId)
        );
        assert_eq!(
            ManagedGithubMappingSource::team(1, "automata-ci", value, "core"),
            Err(GithubMappingValueError::InvalidGithubId)
        );
    }
    assert_eq!(
        ManagedGithubMappingSource::organization(1, "contains space"),
        Err(GithubMappingValueError::InvalidOrganizationLogin)
    );
    assert_eq!(
        ManagedGithubMappingSource::team(1, "automata-ci", 2, "contains/slash"),
        Err(GithubMappingValueError::InvalidTeamSlug)
    );
}

#[test]
fn create_is_tenant_bound_and_debug_omits_display_names() {
    let source =
        ManagedGithubMappingSource::team(10, "private-organization-name", 20, "private-team-slug")
            .expect("source");
    let command = CreateGithubMapping::new(
        actor("tenant-a"),
        mapping_id(1),
        source,
        role_id(2),
        AuthorizationScope::tenant(TenantId::new("tenant-a").expect("tenant")),
    )
    .expect("command");
    let debug = format!("{command:?}");
    assert!(!debug.contains("private-organization-name"));
    assert!(!debug.contains("private-team-slug"));

    let cross_tenant = CreateGithubMapping::new(
        actor("tenant-a"),
        mapping_id(3),
        ManagedGithubMappingSource::organization(10, "automata-ci").expect("source"),
        role_id(4),
        AuthorizationScope::tenant(TenantId::new("tenant-b").expect("tenant")),
    );
    assert_eq!(cross_tenant, Err(GithubMappingValueError::CrossTenantScope));
}

#[test]
fn pages_and_options_reject_oversized_duplicate_or_unordered_results() {
    assert_eq!(
        GithubMappingPage::new(
            vec![record(1), record(2)],
            None,
            GithubMappingPageSize::new(1).expect("limit"),
            revision(1),
        ),
        Err(GithubMappingValueError::OversizedPage)
    );

    let option = |id: u128, name: &str, display_name: &str| {
        DirectBindingRoleOption::new(
            role_id(id),
            RoleName::new(name).expect("name"),
            display_name,
            RoleKind::Custom,
            false,
        )
        .expect("option")
    };
    assert_eq!(
        GithubMappingOptions::new(
            revision(1),
            vec![option(1, "one", "Zulu"), option(2, "two", "Alpha")],
            Vec::new(),
            Vec::new(),
        ),
        Err(GithubMappingValueError::InvalidOptionOrder)
    );
    assert_eq!(
        GithubMappingOptions::new(
            revision(1),
            vec![option(1, "one", "Alpha"), option(1, "one", "Zulu")],
            Vec::new(),
            Vec::new(),
        ),
        Err(GithubMappingValueError::InvalidOptionOrder)
    );

    let oversized = (0..=GITHUB_MAPPING_OPTION_LIMIT)
        .map(|index| {
            option(
                u128::try_from(index).expect("index") + 1,
                &format!("role-{index:03}"),
                &format!("Role {index:03}"),
            )
        })
        .collect();
    assert_eq!(
        GithubMappingOptions::new(revision(1), oversized, Vec::new(), Vec::new()),
        Err(GithubMappingValueError::OversizedOptions)
    );
}

#[test]
fn mapping_management_port_is_object_safe_and_thread_safe() {
    #[allow(dead_code)]
    fn accepts_object(_: &dyn GithubMappingManagementRepository) {}

    assert_impl_all!(GithubMappingPage: Send, Sync);
    assert_impl_all!(CreateGithubMapping: Send, Sync);
}
