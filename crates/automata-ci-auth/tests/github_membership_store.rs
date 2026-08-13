use std::{collections::BTreeSet, sync::Arc};

use automata_ci_auth::{
    github::{
        GithubMembershipObservation, GithubMembershipRepository, GithubMembershipRequestError,
        GithubMembershipSnapshot, GithubMembershipSnapshotId, GithubOrganizationId,
        GithubOrganizationLogin, GithubOrganizationMembership, GithubOrganizationMembershipRole,
        GithubTeam, GithubTeamId, GithubTeamSlug, PersistGithubMembershipSnapshot,
    },
    human::{PrincipalId, ProviderSubject, TenantId},
    time::UnixTimestamp,
    vault::TokenVersion,
};
use uuid::Uuid;

fn memberships() -> GithubMembershipSnapshot {
    let organization_id = GithubOrganizationId::new(10).expect("organization ID");
    let organization_login = GithubOrganizationLogin::new("Automata-CI").expect("login");
    GithubMembershipSnapshot::new(
        [GithubOrganizationMembership::new(
            organization_id,
            organization_login.clone(),
            GithubOrganizationMembershipRole::Admin,
        )],
        [GithubTeam::new(
            GithubTeamId::new(20).expect("team ID"),
            organization_id,
            organization_login,
            GithubTeamSlug::new("Maintainers").expect("slug"),
        )],
    )
    .expect("membership snapshot")
}

fn request(
    principal_id: &str,
    provider_subject: &str,
    observed_at: u64,
    valid_until: u64,
) -> Result<PersistGithubMembershipSnapshot, GithubMembershipRequestError> {
    PersistGithubMembershipSnapshot::new(
        TenantId::new("tenant-a").expect("tenant"),
        PrincipalId::new(principal_id).expect("principal text"),
        ProviderSubject::new(provider_subject).expect("subject text"),
        TokenVersion::new(7).expect("token version"),
        GithubMembershipObservation::new(
            GithubMembershipSnapshotId::from_uuid(
                Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("snapshot UUID"),
            )
            .expect("snapshot ID"),
            memberships(),
            UnixTimestamp::from_seconds(observed_at),
            UnixTimestamp::from_seconds(valid_until),
        )?,
    )
}

#[test]
fn persistence_request_retains_exact_stable_authority() {
    let request = request("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "42", 100, 160).expect("request");
    assert_eq!(request.tenant_id().as_str(), "tenant-a");
    assert_eq!(
        request.principal_uuid(),
        Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("UUID")
    );
    assert_eq!(request.provider_subject().as_str(), "42");
    assert_eq!(request.provider_token_version().value(), 7);
    assert_eq!(request.memberships().organizations().len(), 1);
    assert_eq!(request.memberships().teams().len(), 1);
    assert_eq!(request.observed_at(), UnixTimestamp::from_seconds(100));
    assert_eq!(request.valid_until(), UnixTimestamp::from_seconds(160));
    let debug = format!("{request:?}");
    assert!(debug.contains("organization_count"));
    assert!(!debug.contains("Maintainers"));

    let mut stable_ids = BTreeSet::new();
    stable_ids.extend(
        request
            .memberships()
            .organizations()
            .map(|item| item.id().get()),
    );
    assert_eq!(stable_ids, BTreeSet::from([10]));
}

#[test]
fn uuids_subjects_and_validity_are_canonical_and_closed() {
    assert_eq!(
        GithubMembershipSnapshotId::new("BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"),
        Err(GithubMembershipRequestError::InvalidSnapshotId)
    );
    assert_eq!(
        GithubMembershipSnapshotId::from_uuid(Uuid::nil()),
        Err(GithubMembershipRequestError::InvalidSnapshotId)
    );
    assert_eq!(
        request("not-a-uuid", "42", 100, 160),
        Err(GithubMembershipRequestError::InvalidPrincipalId)
    );
    assert_eq!(
        request("00000000-0000-0000-0000-000000000000", "42", 100, 160),
        Err(GithubMembershipRequestError::InvalidPrincipalId)
    );
    for subject in ["0", "042", "+42", "octocat"] {
        assert_eq!(
            request("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", subject, 100, 160,),
            Err(GithubMembershipRequestError::InvalidProviderSubject)
        );
    }
    assert_eq!(
        request("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "42", 100, 100,),
        Err(GithubMembershipRequestError::InvalidValidity)
    );
}

#[test]
fn persistence_port_is_runtime_pluggable() {
    fn accepts_port(_: Arc<dyn GithubMembershipRepository>) {}
    let _ = accepts_port;
}
