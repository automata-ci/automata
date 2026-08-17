use automata_ci_provider::{
    AuthorizationCodeLoginCapability, ChangedFileCapability, ChangedFileCompleteness,
    CommitStatusCapability, CommitStatusState, ExternalDeliveryId, ExternalDeliveryIdentity,
    ExternalRepositoryId, ExternalRepositoryIdentity, ExternalSubjectId, ExternalSubjectIdentity,
    ExternalSubjectKind, MembershipEvidenceCapability, PkceSupport, ProviderCapabilities,
    ProviderCapabilitiesError, ProviderCapability, ProviderCapabilityKind, ProviderConnectionId,
    ProviderIdentityError, ProviderInstanceId, ProviderTypeId, RepositoryEventCapability,
    RepositoryEventKind, RichCheckCapability, StatusHistoryModel, WorkloadCredentialCapability,
    WorkloadCredentialProfile, WorkloadCredentialRevocation,
};
use uuid::Uuid;

fn full_capabilities() -> ProviderCapabilities {
    let events = RepositoryEventCapability::new([
        RepositoryEventKind::Push,
        RepositoryEventKind::PullRequest,
    ])
    .expect("events");
    let changes = ChangedFileCapability::new(
        [RepositoryEventKind::Push, RepositoryEventKind::PullRequest],
        ChangedFileCompleteness::ExplicitlyIncomplete,
    )
    .expect("changed files");
    let status = CommitStatusCapability::new(
        [
            CommitStatusState::Pending,
            CommitStatusState::Success,
            CommitStatusState::Failure,
            CommitStatusState::Error,
        ],
        StatusHistoryModel::AppendOnly,
    )
    .expect("commit status");
    let checks = RichCheckCapability::new(true, true, true).expect("rich checks");
    let workload = WorkloadCredentialCapability::new(
        [WorkloadCredentialProfile::CheckoutRead],
        [WorkloadCredentialRevocation::Explicit],
    )
    .expect("workload credentials");
    let membership = MembershipEvidenceCapability::new([
        ExternalSubjectKind::Organization,
        ExternalSubjectKind::Team,
    ])
    .expect("membership");
    ProviderCapabilities::new([
        ProviderCapability::SourceRead,
        ProviderCapability::RepositoryEvents(events),
        ProviderCapability::ChangedFiles(changes),
        ProviderCapability::CommitStatus(status),
        ProviderCapability::RichChecks(checks),
        ProviderCapability::WorkloadCredentials(workload),
        ProviderCapability::AuthorizationCodeLogin(AuthorizationCodeLoginCapability::new(
            PkceSupport::Supported,
            true,
        )),
        ProviderCapability::MembershipEvidence(membership),
        ProviderCapability::ManagedWebhook,
    ])
    .expect("full capabilities")
}

#[test]
fn provider_type_uses_canonical_extensible_syntax() {
    for valid in ["github", "forgejo", "gitlab-self-hosted", "provider2"] {
        let provider_type = ProviderTypeId::new(valid).expect("valid provider type");
        assert_eq!(provider_type.as_str(), valid);
        assert_eq!(provider_type.to_string(), valid);
    }
    for invalid in [
        "",
        "GitHub",
        "-github",
        "github-",
        "github--enterprise",
        "1github",
        "git_hub",
        "github.com",
        "github/enterprise",
        " github",
    ] {
        assert!(
            ProviderTypeId::new(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn durable_provider_ids_reject_nil_in_construction_parsing_and_serde() {
    assert_eq!(
        ProviderInstanceId::from_uuid(Uuid::nil()),
        Err(ProviderIdentityError::NilUuid("provider instance ID"))
    );
    assert_eq!(
        ProviderConnectionId::from_uuid(Uuid::nil()),
        Err(ProviderIdentityError::NilUuid("provider connection ID"))
    );
    assert!(
        "00000000-0000-0000-0000-000000000000"
            .parse::<ProviderInstanceId>()
            .is_err()
    );
    assert!(
        serde_json::from_str::<ProviderConnectionId>("\"00000000-0000-0000-0000-000000000000\"")
            .is_err()
    );

    let value = Uuid::from_u128(42);
    let instance = ProviderInstanceId::from_uuid(value).expect("instance");
    assert_eq!(instance.as_uuid(), value);
    let json = serde_json::to_string(&instance).expect("serialize");
    assert_eq!(
        serde_json::from_str::<ProviderInstanceId>(&json).expect("deserialize"),
        instance
    );
}

#[test]
fn external_ids_are_opaque_bounded_and_distinct() {
    assert_eq!(
        ExternalRepositoryId::new("42")
            .expect("repository")
            .as_str(),
        "42"
    );
    assert_eq!(
        ExternalSubjectId::new("group/project/user")
            .expect("subject")
            .as_str(),
        "group/project/user"
    );
    assert_eq!(
        ExternalDeliveryId::new("delivery:01")
            .expect("delivery")
            .as_str(),
        "delivery:01"
    );
    for invalid in ["", " value", "value ", "line\nbreak"] {
        assert!(ExternalRepositoryId::new(invalid).is_err());
    }
}

#[test]
fn external_identities_are_namespaced_by_provider_instance() {
    let first = ProviderInstanceId::from_uuid(Uuid::from_u128(1)).expect("first instance");
    let second = ProviderInstanceId::from_uuid(Uuid::from_u128(2)).expect("second instance");

    let repository_id = ExternalRepositoryId::new("42").expect("repository");
    let first_repository = ExternalRepositoryIdentity::new(first, repository_id.clone());
    let second_repository = ExternalRepositoryIdentity::new(second, repository_id);
    assert_ne!(first_repository, second_repository);

    let subject_id = ExternalSubjectId::new("1").expect("subject");
    let user = ExternalSubjectIdentity::new(first, ExternalSubjectKind::User, subject_id.clone());
    let team = ExternalSubjectIdentity::new(first, ExternalSubjectKind::Team, subject_id);
    assert_ne!(user, team);

    let delivery_id = ExternalDeliveryId::new("same-uuid").expect("delivery");
    let first_delivery = ExternalDeliveryIdentity::new(first, delivery_id.clone());
    let second_delivery = ExternalDeliveryIdentity::new(second, delivery_id);
    assert_ne!(first_delivery, second_delivery);

    let json = serde_json::to_string(&first_repository).expect("serialize repository identity");
    assert_eq!(
        serde_json::from_str::<ExternalRepositoryIdentity>(&json)
            .expect("deserialize repository identity"),
        first_repository
    );
}

#[test]
fn capability_set_is_typed_ordered_and_round_trips() {
    let capabilities = full_capabilities();
    assert_eq!(capabilities.len(), 9);
    assert!(capabilities.contains(ProviderCapabilityKind::SourceRead));
    assert!(capabilities.contains(ProviderCapabilityKind::ManagedWebhook));
    let kinds = capabilities
        .iter()
        .map(ProviderCapability::kind)
        .collect::<Vec<_>>();
    assert!(kinds.windows(2).all(|pair| pair[0] < pair[1]));

    let json = serde_json::to_string(&capabilities).expect("serialize capabilities");
    assert_eq!(
        serde_json::from_str::<ProviderCapabilities>(&json).expect("deserialize capabilities"),
        capabilities
    );
}

#[test]
fn capability_set_rejects_duplicates_and_cross_capability_lies() {
    assert_eq!(
        ProviderCapabilities::new(Vec::new()),
        Err(ProviderCapabilitiesError::EmptyCapabilities)
    );
    assert_eq!(
        ProviderCapabilities::new([
            ProviderCapability::SourceRead,
            ProviderCapability::SourceRead,
        ]),
        Err(ProviderCapabilitiesError::DuplicateCapability(
            ProviderCapabilityKind::SourceRead
        ))
    );
    let changes = ChangedFileCapability::new(
        [RepositoryEventKind::Push],
        ChangedFileCompleteness::Complete,
    )
    .expect("changed files");
    assert_eq!(
        ProviderCapabilities::new([ProviderCapability::ChangedFiles(changes.clone())]),
        Err(ProviderCapabilitiesError::ChangedFilesWithoutEvents)
    );
    let pull_requests =
        RepositoryEventCapability::new([RepositoryEventKind::PullRequest]).expect("pull requests");
    assert_eq!(
        ProviderCapabilities::new([
            ProviderCapability::RepositoryEvents(pull_requests),
            ProviderCapability::ChangedFiles(changes),
        ]),
        Err(ProviderCapabilitiesError::ChangedFilesOutsideEvents)
    );
    assert_eq!(
        ProviderCapabilities::new([ProviderCapability::ManagedWebhook]),
        Err(ProviderCapabilitiesError::ManagedWebhookWithoutEvents)
    );
}

#[test]
fn capability_deserialization_revalidates_nested_documents() {
    for invalid in [
        r#"[{"kind":"repository_events","configuration":{"events":[]}}]"#,
        r#"[{"kind":"commit_status","configuration":{"states":[],"history_model":"mutable"}}]"#,
        r#"[{"kind":"rich_checks","configuration":{"annotations":false,"external_actions":false,"native_rerun":false}}]"#,
        r#"[{"kind":"workload_credentials","configuration":{"profiles":[],"revocation":["explicit"]}}]"#,
        r#"[{"kind":"membership_evidence","configuration":{"subject_kinds":[]}}]"#,
    ] {
        assert!(
            serde_json::from_str::<ProviderCapabilities>(invalid).is_err(),
            "accepted {invalid}"
        );
    }

    assert!(serde_json::from_str::<RepositoryEventCapability>(r#"{"events":[]}"#).is_err());
    assert!(
        serde_json::from_str::<RichCheckCapability>(
            r#"{"annotations":false,"external_actions":true,"native_rerun":true,"unknown":false}"#
        )
        .is_err()
    );
}
