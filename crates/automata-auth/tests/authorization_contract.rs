use std::collections::{BTreeMap, BTreeSet};

use automata_auth::{
    authorization::{Permission, RbacPolicy, RoleName},
    github::{
        GithubMembershipSnapshot, GithubOrganizationName, GithubRoleMapper, GithubRoleMapping,
        GithubRoleSource, GithubTeam, GithubTeamSlug,
    },
};

fn role(value: &str) -> RoleName {
    RoleName::new(value).expect("valid role")
}

fn roles(values: &[&str]) -> BTreeSet<RoleName> {
    values.iter().map(|value| role(value)).collect()
}

#[test]
fn github_membership_grants_only_explicitly_mapped_roles() {
    let organization = GithubOrganizationName::new("Automata-Org").expect("organization");
    let team_slug = GithubTeamSlug::new("CI-Operators").expect("team slug");
    let memberships = GithubMembershipSnapshot::new(
        BTreeSet::from([organization.clone()]),
        BTreeSet::from([GithubTeam {
            organization: organization.clone(),
            slug: team_slug.clone(),
        }]),
    )
    .expect("membership snapshot");
    let mapper = GithubRoleMapper::new([
        GithubRoleMapping::new(
            GithubRoleSource::Team {
                organization: organization.clone(),
                team: team_slug,
            },
            roles(&["run-operator"]),
        )
        .expect("team mapping"),
        GithubRoleMapping::new(
            GithubRoleSource::Organization {
                organization: GithubOrganizationName::new("unrelated").expect("organization"),
            },
            roles(&["administrator"]),
        )
        .expect("unrelated mapping"),
    ])
    .expect("role mapper");

    assert_eq!(mapper.roles_for(&memberships), roles(&["run-operator"]));
    assert_eq!(organization.as_str(), "automata-org");
}

#[test]
fn an_unmapped_owner_or_team_has_no_implicit_role() {
    let organization = GithubOrganizationName::new("automata").expect("organization");
    let memberships =
        GithubMembershipSnapshot::new(BTreeSet::from([organization]), BTreeSet::new())
            .expect("membership snapshot");
    let mapper = GithubRoleMapper::default();
    assert!(mapper.roles_for(&memberships).is_empty());
}

#[test]
fn team_snapshot_requires_the_containing_organization() {
    let organization = GithubOrganizationName::new("automata").expect("organization");
    let result = GithubMembershipSnapshot::new(
        BTreeSet::new(),
        BTreeSet::from([GithubTeam {
            organization,
            slug: GithubTeamSlug::new("operators").expect("team slug"),
        }]),
    );
    assert!(result.is_err());
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
