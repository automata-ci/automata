use automata_ci_core::{
    AttemptId, AttemptNumber, FencingToken, GitObjectAlgorithm, JobId, Lease, LeaseId,
    PermissionLevel, RunnerId, Sha256Digest, TrustSourceClass, UnixMillis, WorkspaceId,
};
use automata_ci_provider::{
    AuthorizationCodeRequest, ControlCredential, ControlCredentialRequest,
    ControlCredentialRevocation, ControlCredentialStrategy, ExternalRepositoryId,
    ExternalRepositoryIdentity, ExternalSubjectId, ExternalSubjectIdentity, ExternalSubjectKind,
    IssuedWorkloadCredential, ProviderArchiveLimits, ProviderCallbackUri, ProviderCapabilities,
    ProviderCapability, ProviderCapabilityKind, ProviderConfigurationRevision,
    ProviderConnectionConfiguration, ProviderConnectionId, ProviderConnectionManifest,
    ProviderConnectionPolicyDocument, ProviderConnectionRevision, ProviderControlCredentialId,
    ProviderControlOperation, ProviderControlOperationSet, ProviderCredentialGeneration,
    ProviderDefaultBranch, ProviderHumanCredential, ProviderHumanIdentity, ProviderInstanceId,
    ProviderLifecycleState, ProviderMembership, ProviderMembershipSnapshot, ProviderPkceVerifier,
    ProviderRepositoryPath, ProviderRunnerPolicyBinding, ProviderSchemaVersion,
    ProviderWorkflowSource, ProviderWorkloadCredentialId, RepositoryVisibility,
    SourceReadCapability, WorkloadCredentialPermission, WorkloadCredentialPermissionSet,
    WorkloadCredentialProfile, WorkloadCredentialRequest, WorkloadCredentialRevocation,
};
use automata_ci_secret::SecretValue;
use static_assertions::assert_not_impl_any;
use url::Url;
use uuid::Uuid;

assert_not_impl_any!(ControlCredential: Clone, serde::Serialize);
assert_not_impl_any!(IssuedWorkloadCredential: Clone, serde::Serialize);
assert_not_impl_any!(ProviderHumanCredential: Clone, serde::Serialize);
assert_not_impl_any!(ProviderPkceVerifier: Clone, serde::Serialize);
assert_not_impl_any!(automata_ci_provider::ProviderAuthorizationUrl: Clone, serde::Serialize);

fn instance(value: u128) -> ProviderInstanceId {
    ProviderInstanceId::from_uuid(Uuid::from_u128(value)).unwrap()
}

fn connection() -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        ExternalRepositoryIdentity::new(instance(2), ExternalRepositoryId::new("repo-42").unwrap()),
        ProviderConfigurationRevision::new(3).unwrap(),
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").unwrap(),
        ProviderWorkflowSource::Directory(ProviderRepositoryPath::new(".ci/workflows").unwrap()),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).unwrap(),
            Sha256Digest::from_bytes([5; 32]),
        ),
        ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024).unwrap(),
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(1).unwrap(),
            b"{}".to_vec(),
        )
        .unwrap(),
    );
    ProviderConnectionManifest::new(
        ProviderConnectionId::from_uuid(Uuid::from_u128(3)).unwrap(),
        ProviderConnectionRevision::new(7).unwrap(),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(1_000),
        Some(UnixMillis::new(1_001)),
        None,
    )
    .unwrap()
}

fn secret(value: &str) -> SecretValue {
    SecretValue::from_utf8(value.to_owned()).unwrap()
}

fn lease() -> Lease {
    Lease::new(
        LeaseId::from_uuid(Uuid::from_u128(11)),
        AttemptId::from_uuid(Uuid::from_u128(12)),
        RunnerId::from_uuid(Uuid::from_u128(13)),
        FencingToken::new(4).unwrap(),
        UnixMillis::new(2_000),
        UnixMillis::new(5_000),
    )
    .unwrap()
}

#[test]
fn control_credentials_are_exact_operation_scoped_and_secret_safe() {
    let operations = ProviderControlOperationSet::new([
        ProviderControlOperation::RepositoryRead,
        ProviderControlOperation::ResultWrite,
    ])
    .unwrap();
    let request = ControlCredentialRequest::new(
        ProviderControlCredentialId::from_uuid(Uuid::from_u128(20)).unwrap(),
        &connection(),
        operations.clone(),
        UnixMillis::new(2_000),
        1_000,
    )
    .unwrap();
    let credential = ControlCredential::new(
        &request,
        operations,
        ControlCredentialStrategy::Minted,
        ProviderCredentialGeneration::new(1).unwrap(),
        secret("control-secret-that-must-not-leak"),
        UnixMillis::new(2_001),
        Some(UnixMillis::new(4_000)),
        ControlCredentialRevocation::ProviderExpiry,
    )
    .unwrap();
    assert!(credential.permits(ProviderControlOperation::RepositoryRead));
    assert!(!credential.permits(ProviderControlOperation::MembershipRead));
    assert_eq!(credential.request_digest(), request.digest());
    assert!(!format!("{credential:?}").contains("must-not-leak"));
}

#[test]
fn workload_authority_is_lease_bound_and_write_requires_same_repository_trust() {
    let write = WorkloadCredentialPermissionSet::new([WorkloadCredentialPermission::new(
        "contents",
        PermissionLevel::Write,
    )
    .unwrap()])
    .unwrap();
    let build = |trust_class| {
        WorkloadCredentialRequest::new(
            ProviderWorkloadCredentialId::from_uuid(Uuid::from_u128(21)).unwrap(),
            &connection(),
            JobId::from_uuid(Uuid::from_u128(22)),
            AttemptNumber::new(1).unwrap(),
            lease(),
            trust_class,
            WorkloadCredentialProfile::RepositoryWrite,
            write.clone(),
            UnixMillis::new(2_001),
            UnixMillis::new(4_000),
        )
    };
    assert!(build(TrustSourceClass::Fork).is_err());
    let request = build(TrustSourceClass::SameRepository).unwrap();
    assert_eq!(
        request.lease().fencing_token(),
        FencingToken::new(4).unwrap()
    );
    assert!(request.marker().as_str().starts_with("automata-workload:"));
    let issued = IssuedWorkloadCredential::new(
        &request,
        None,
        secret("workload-secret-that-must-not-leak"),
        UnixMillis::new(2_002),
        Some(UnixMillis::new(4_500)),
        WorkloadCredentialRevocation::ProviderExpiry,
    )
    .unwrap();
    assert_eq!(issued.request_digest(), request.digest());
    assert!(!format!("{issued:?}").contains("must-not-leak"));
}

#[test]
fn authorization_code_requests_require_literal_loopback_and_s256_pkce() {
    assert!(
        ProviderCallbackUri::loopback(Url::parse("http://localhost:9123/callback").unwrap())
            .is_err()
    );
    let callback =
        ProviderCallbackUri::loopback(Url::parse("http://127.0.0.1:9123/callback").unwrap())
            .unwrap();
    let verifier =
        ProviderPkceVerifier::new("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG".to_owned())
            .unwrap();
    let challenge = verifier.s256_challenge();
    assert_eq!(challenge.len(), 43);
    assert!(!challenge.contains('='));
    let request = AuthorizationCodeRequest::new(
        instance(30),
        callback,
        secret("independent-state"),
        secret("independent-nonce"),
        verifier,
        UnixMillis::new(1_000),
        UnixMillis::new(61_000),
    )
    .unwrap();
    let debug = format!("{request:?}");
    assert!(!debug.contains("independent-state"));
    assert!(!debug.contains("independent-nonce"));
    assert!(
        AuthorizationCodeRequest::new(
            instance(30),
            ProviderCallbackUri::web(Url::parse("https://ci.example/callback").unwrap()).unwrap(),
            secret("same-proof"),
            secret("same-proof"),
            ProviderPkceVerifier::new("0123456789abcdefghijklmnopqrstuvwxyzABCDEFG".to_owned())
                .unwrap(),
            UnixMillis::new(1_000),
            UnixMillis::new(61_000),
        )
        .is_err()
    );
}

#[test]
fn membership_snapshots_are_instance_scoped_complete_hierarchies() {
    let user = ExternalSubjectIdentity::new(
        instance(40),
        ExternalSubjectKind::User,
        ExternalSubjectId::new("user-1").unwrap(),
    );
    let identity = ProviderHumanIdentity::new(
        user,
        "alice",
        Some("Alice".to_owned()),
        UnixMillis::new(2_000),
    )
    .unwrap();
    let organization = ExternalSubjectIdentity::new(
        instance(40),
        ExternalSubjectKind::Organization,
        ExternalSubjectId::new("org-1").unwrap(),
    );
    let team = ExternalSubjectIdentity::new(
        instance(40),
        ExternalSubjectKind::Team,
        ExternalSubjectId::new("team-1").unwrap(),
    );
    let organization_membership =
        ProviderMembership::new(organization.clone(), None, None).unwrap();
    let team_membership = ProviderMembership::new(team, Some(organization), None).unwrap();
    let snapshot = ProviderMembershipSnapshot::new(
        identity,
        [team_membership, organization_membership],
        UnixMillis::new(2_001),
    )
    .unwrap();
    assert_eq!(snapshot.memberships().len(), 2);

    let other = ExternalSubjectIdentity::new(
        instance(41),
        ExternalSubjectKind::Organization,
        ExternalSubjectId::new("other-org").unwrap(),
    );
    assert!(
        ProviderMembership::new(
            ExternalSubjectIdentity::new(
                instance(40),
                ExternalSubjectKind::Team,
                ExternalSubjectId::new("team-2").unwrap()
            ),
            Some(other),
            None,
        )
        .is_err()
    );
}

#[test]
fn absent_credential_and_login_capabilities_remain_absent() {
    let capabilities = ProviderCapabilities::new([ProviderCapability::SourceRead(
        SourceReadCapability::new([GitObjectAlgorithm::Sha1]).unwrap(),
    )])
    .unwrap();
    assert!(!capabilities.contains(ProviderCapabilityKind::WorkloadCredentials));
    assert!(!capabilities.contains(ProviderCapabilityKind::AuthorizationCodeLogin));
    assert!(!capabilities.contains(ProviderCapabilityKind::DeviceAuthorizationLogin));
    assert!(!capabilities.contains(ProviderCapabilityKind::MembershipEvidence));
}
