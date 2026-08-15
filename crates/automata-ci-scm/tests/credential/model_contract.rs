use automata_ci_auth::{secret::SecretString, time::UnixTimestamp};
use automata_ci_scm::{
    RepositoryId, ScmProviderId,
    credential::{
        CredentialProvenance, IssuedRepositoryCredential, MinimumValidity, ModelError,
        PermissionLevel, PermissionName, PermissionSet, ProviderResourceId,
        RepositoryCredentialRequest, RepositoryScope, WorkloadIdentity,
    },
};

fn request() -> RepositoryCredentialRequest {
    RepositoryCredentialRequest::new(
        WorkloadIdentity::new("tenant/run/job/attempt-1").unwrap(),
        RepositoryScope::new(
            ScmProviderId::new("github").unwrap(),
            RepositoryId::new("automata-ci/automata").unwrap(),
            ProviderResourceId::new("81234567").unwrap(),
        ),
        PermissionSet::new([
            (
                PermissionName::new("contents").unwrap(),
                PermissionLevel::Read,
            ),
            (
                PermissionName::new("statuses").unwrap(),
                PermissionLevel::Write,
            ),
        ])
        .unwrap(),
        MinimumValidity::from_seconds(300).unwrap(),
    )
}

#[test]
fn values_are_canonical_bounded_and_duplicate_free() {
    assert!(WorkloadIdentity::new("").is_err());
    assert!(WorkloadIdentity::new("run secret\n").is_err());
    assert_eq!(
        ProviderResourceId::new("owner/repository").unwrap_err(),
        ModelError::InvalidProviderResourceId
    );
    assert!(PermissionName::new("Contents").is_err());
    assert!(PermissionName::new("bad__name").is_err());
    assert!(MinimumValidity::from_seconds(0).is_err());
    assert!(MinimumValidity::from_seconds(3_601).is_err());

    let name = PermissionName::new("contents").unwrap();
    assert!(
        PermissionSet::new([
            (name.clone(), PermissionLevel::Read),
            (name, PermissionLevel::Write),
        ])
        .is_err()
    );
    assert!(PermissionSet::new([]).is_err());
}

#[test]
fn issued_secret_is_exactly_bound_and_redacted() {
    let request = request();
    let issued = IssuedRepositoryCredential::new(
        SecretString::new("ghs_future_variable_length_token").unwrap(),
        &request,
        UnixTimestamp::from_seconds(1_000),
        UnixTimestamp::from_seconds(1_300),
        CredentialProvenance::new(
            ScmProviderId::new("github").unwrap(),
            ProviderResourceId::new("Iv1.automata").unwrap(),
            ProviderResourceId::new("998877").unwrap(),
        ),
    )
    .unwrap();

    assert_eq!(issued.workload(), request.workload());
    assert_eq!(issued.repository(), request.repository());
    assert_eq!(issued.permissions(), request.permissions());
    assert_eq!(issued.expires_at(), UnixTimestamp::from_seconds(1_300));
    let rendered = format!("{issued:?}");
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("ghs_future_variable_length_token"));
}

#[test]
fn issued_secret_fails_closed_on_provider_or_expiration_drift() {
    let request = request();
    let secret = || SecretString::new("ghs_secret").unwrap();
    let wrong_provider = CredentialProvenance::new(
        ScmProviderId::new("gitlab").unwrap(),
        ProviderResourceId::new("issuer").unwrap(),
        ProviderResourceId::new("subject").unwrap(),
    );
    assert!(
        IssuedRepositoryCredential::new(
            secret(),
            &request,
            UnixTimestamp::from_seconds(1_000),
            UnixTimestamp::from_seconds(1_300),
            wrong_provider,
        )
        .is_err()
    );

    let github = CredentialProvenance::new(
        ScmProviderId::new("github").unwrap(),
        ProviderResourceId::new("issuer").unwrap(),
        ProviderResourceId::new("subject").unwrap(),
    );
    assert!(
        IssuedRepositoryCredential::new(
            secret(),
            &request,
            UnixTimestamp::from_seconds(1_000),
            UnixTimestamp::from_seconds(1_299),
            github,
        )
        .is_err()
    );
}
