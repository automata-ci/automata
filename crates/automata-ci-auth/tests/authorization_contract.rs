use std::collections::{BTreeMap, BTreeSet};

use automata_ci_auth::{
    authorization::{Permission, RbacPolicy, RoleName},
    github::{
        GithubMembershipSnapshot, GithubOrganizationId, GithubOrganizationLogin,
        GithubOrganizationMembership, GithubOrganizationMembershipRole, GithubRoleMapper,
        GithubRoleMapping, GithubRoleMappingError, GithubRoleSource, GithubTeam, GithubTeamId,
        GithubTeamSlug,
    },
};

fn role(value: &str) -> RoleName {
    RoleName::new(value).expect("valid role")
}

fn roles(values: &[&str]) -> BTreeSet<RoleName> {
    values.iter().map(|value| role(value)).collect()
}

fn organization(
    id: i64,
    login: &str,
    role: GithubOrganizationMembershipRole,
) -> GithubOrganizationMembership {
    GithubOrganizationMembership::new(
        GithubOrganizationId::new(id).expect("organization ID"),
        GithubOrganizationLogin::new(login).expect("organization login"),
        role,
    )
}

fn team(id: i64, organization_id: i64, organization_login: &str, slug: &str) -> GithubTeam {
    GithubTeam::new(
        GithubTeamId::new(id).expect("team ID"),
        GithubOrganizationId::new(organization_id).expect("organization ID"),
        GithubOrganizationLogin::new(organization_login).expect("organization login"),
        GithubTeamSlug::new(slug).expect("team slug"),
    )
}

#[test]
fn github_membership_grants_only_explicitly_mapped_roles() {
    let organization_id = GithubOrganizationId::new(44).expect("organization ID");
    let team_id = GithubTeamId::new(91).expect("team ID");
    let memberships = GithubMembershipSnapshot::new(
        [organization(
            organization_id.get(),
            "Automata-Org",
            GithubOrganizationMembershipRole::Admin,
        )],
        [team(
            team_id.get(),
            organization_id.get(),
            "Automata-Org",
            "CI-Operators",
        )],
    )
    .expect("membership snapshot");
    let mapper = GithubRoleMapper::new([
        GithubRoleMapping::new(
            GithubRoleSource::Team {
                organization_id,
                team_id,
            },
            roles(&["run-operator"]),
        )
        .expect("team mapping"),
        GithubRoleMapping::new(
            GithubRoleSource::Organization {
                organization_id: GithubOrganizationId::new(45).expect("organization ID"),
            },
            roles(&["administrator"]),
        )
        .expect("unrelated mapping"),
    ])
    .expect("role mapper");

    assert_eq!(mapper.roles_for(&memberships), roles(&["run-operator"]));
    assert_eq!(
        memberships
            .organization(organization_id)
            .expect("organization")
            .login()
            .as_str(),
        "automata-org"
    );
}

#[test]
fn an_unmapped_owner_or_team_has_no_implicit_role() {
    let memberships = GithubMembershipSnapshot::new(
        [organization(
            44,
            "automata",
            GithubOrganizationMembershipRole::Admin,
        )],
        [],
    )
    .expect("membership snapshot");
    let mapper = GithubRoleMapper::default();
    assert!(mapper.roles_for(&memberships).is_empty());
}

#[test]
fn team_snapshot_requires_the_containing_organization() {
    let result = GithubMembershipSnapshot::new([], [team(91, 44, "automata", "operators")]);
    assert_eq!(result, Err(GithubRoleMappingError::TeamWithoutOrganization));
}

#[test]
fn mutable_github_names_never_participate_in_role_authority() {
    let organization_id = GithubOrganizationId::new(44).expect("organization ID");
    let team_id = GithubTeamId::new(91).expect("team ID");
    let mapper = GithubRoleMapper::new([
        GithubRoleMapping::new(
            GithubRoleSource::Organization { organization_id },
            roles(&["organization-reader"]),
        )
        .expect("organization mapping"),
        GithubRoleMapping::new(
            GithubRoleSource::Team {
                organization_id,
                team_id,
            },
            roles(&["run-operator"]),
        )
        .expect("team mapping"),
    ])
    .expect("role mapper");

    let after_renames = GithubMembershipSnapshot::new(
        [organization(
            44,
            "new-organization-login",
            GithubOrganizationMembershipRole::Member,
        )],
        [team(91, 44, "new-organization-login", "renamed-team")],
    )
    .expect("renamed membership snapshot");

    assert_eq!(
        mapper.roles_for(&after_renames),
        roles(&["organization-reader", "run-operator"])
    );
}

#[test]
fn identical_names_with_different_ids_never_match_a_mapping() {
    let mapped_organization_id = GithubOrganizationId::new(44).expect("organization ID");
    let mapped_team_id = GithubTeamId::new(91).expect("team ID");
    let mapper = GithubRoleMapper::new([GithubRoleMapping::new(
        GithubRoleSource::Team {
            organization_id: mapped_organization_id,
            team_id: mapped_team_id,
        },
        roles(&["run-operator"]),
    )
    .expect("team mapping")])
    .expect("role mapper");
    let impersonating_names = GithubMembershipSnapshot::new(
        [organization(
            45,
            "automata",
            GithubOrganizationMembershipRole::Admin,
        )],
        [team(92, 45, "automata", "operators")],
    )
    .expect("membership snapshot");

    assert!(mapper.roles_for(&impersonating_names).is_empty());
}

#[test]
fn membership_snapshots_reject_duplicate_and_conflicting_relationships() {
    let duplicate_organization = GithubMembershipSnapshot::new(
        [
            organization(44, "automata", GithubOrganizationMembershipRole::Member),
            organization(44, "renamed", GithubOrganizationMembershipRole::Admin),
        ],
        [],
    );
    assert_eq!(
        duplicate_organization,
        Err(GithubRoleMappingError::DuplicateOrganizationId)
    );

    let conflicting_login = GithubMembershipSnapshot::new(
        [
            organization(44, "automata", GithubOrganizationMembershipRole::Member),
            organization(45, "automata", GithubOrganizationMembershipRole::Member),
        ],
        [],
    );
    assert_eq!(
        conflicting_login,
        Err(GithubRoleMappingError::ConflictingOrganizationLogin)
    );

    let parent_mismatch = GithubMembershipSnapshot::new(
        [organization(
            44,
            "automata",
            GithubOrganizationMembershipRole::Member,
        )],
        [team(91, 44, "lookalike", "operators")],
    );
    assert_eq!(
        parent_mismatch,
        Err(GithubRoleMappingError::TeamOrganizationMismatch)
    );

    let duplicate_team = GithubMembershipSnapshot::new(
        [organization(
            44,
            "automata",
            GithubOrganizationMembershipRole::Member,
        )],
        [
            team(91, 44, "automata", "operators"),
            team(91, 44, "automata", "renamed"),
        ],
    );
    assert_eq!(duplicate_team, Err(GithubRoleMappingError::DuplicateTeamId));

    let conflicting_slug = GithubMembershipSnapshot::new(
        [organization(
            44,
            "automata",
            GithubOrganizationMembershipRole::Member,
        )],
        [
            team(91, 44, "automata", "operators"),
            team(92, 44, "automata", "operators"),
        ],
    );
    assert_eq!(
        conflicting_slug,
        Err(GithubRoleMappingError::ConflictingTeamSlug)
    );
}

#[test]
fn github_numeric_ids_must_be_positive_in_constructors_and_settings_json() {
    assert!(GithubOrganizationId::new(0).is_err());
    assert!(GithubTeamId::new(-1).is_err());
    assert!(
        serde_json::from_str::<GithubRoleSource>(r#"{"kind":"organization","organization_id":0}"#)
            .is_err()
    );
}

#[test]
fn no_role_name_has_a_hard_coded_authorization_bypass() {
    let administrator = role("administrator");
    let runs_cancel = Permission::new("runs:cancel").expect("permission");
    let empty_policy = RbacPolicy::default();
    assert!(!empty_policy.allows([&administrator], &runs_cancel));

    let operator = role("operator");
    let policy = RbacPolicy::new(BTreeMap::from([(
        operator.clone(),
        BTreeSet::from([runs_cancel.clone()]),
    )]));
    assert!(policy.allows([&operator], &runs_cancel));
    assert!(!policy.allows([&administrator], &runs_cancel));
}

#[test]
fn policy_names_reject_wild_or_invisible_input() {
    assert!(RoleName::new("").is_err());
    assert!(RoleName::new("admin/*").is_err());
    assert!(Permission::new("runs:\ncancel").is_err());
}
