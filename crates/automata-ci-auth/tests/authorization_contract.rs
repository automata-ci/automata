use std::collections::{BTreeMap, BTreeSet};

use automata_ci_auth::{
    authorization::{Permission, RbacPolicy, RoleName},
    github::{
        GithubMembershipSnapshot, GithubOrganizationId, GithubOrganizationLogin,
        GithubOrganizationMembership, GithubOrganizationMembershipRole, GithubRoleMappingError,
        GithubTeam, GithubTeamId, GithubTeamSlug,
    },
};

fn role(value: &str) -> RoleName {
    RoleName::new(value).expect("valid role")
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
fn github_membership_snapshot_uses_stable_id_lookups_and_normalized_metadata() {
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

    let organization = memberships
        .organization(organization_id)
        .expect("organization");
    assert_eq!(organization.login().as_str(), "automata-org");
    assert_eq!(organization.role(), GithubOrganizationMembershipRole::Admin);
    let team = memberships.team(team_id).expect("team");
    assert_eq!(team.organization_id(), organization_id);
    assert_eq!(team.organization_login().as_str(), "automata-org");
    assert_eq!(team.slug().as_str(), "ci-operators");
}

#[test]
fn team_snapshot_requires_the_containing_organization() {
    let result = GithubMembershipSnapshot::new([], [team(91, 44, "automata", "operators")]);
    assert_eq!(result, Err(GithubRoleMappingError::TeamWithoutOrganization));
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
fn github_numeric_ids_must_be_positive_in_constructors_and_json() {
    assert!(GithubOrganizationId::new(0).is_err());
    assert!(GithubTeamId::new(-1).is_err());
    assert!(serde_json::from_str::<GithubOrganizationId>("0").is_err());
    assert!(serde_json::from_str::<GithubTeamId>("-1").is_err());
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
