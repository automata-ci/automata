use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_key_management::{EncryptedEnvelope, KeyId, WrappedDataKey};
use automata_ci_provider::ProviderConnectionId;
use automata_ci_store::{
    AcquireGithubServerServiceHandoff, ClaimNextGithubServerServiceMaintenance,
    FinishGithubServerServiceMint, GithubRepositoryName, GithubServerServiceAction,
    GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceAuthorityDescriptor, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository,
    GithubServerServiceAuthoritySelector, GithubServerServiceAuthorityState,
    GithubServerServiceClaim, GithubServerServiceClaimFence, GithubServerServiceConsumerClaim,
    GithubServerServiceConsumerId, GithubServerServiceCredentialHandoff,
    GithubServerServiceEnvelopeMetadata, GithubServerServiceGeneration,
    GithubServerServiceHandoffId, GithubServerServiceIssuanceKey,
    GithubServerServiceIssuanceReceipt, GithubServerServiceIssuanceState,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubServerServiceScope,
    GithubServerServiceValueError, GithubServerServiceWorkerId,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, MAX_GITHUB_SERVICE_HANDOFF_MILLIS,
    MAX_GITHUB_SERVICE_PLAINTEXT_BYTES, MIN_GITHUB_SERVICE_READY_USE_MILLIS,
    ProtectedGithubServerServiceCredential, ProviderInstallationId, ProviderRepositoryId,
    RepositoryId, TenantScope,
};
use uuid::Uuid;

#[test]
fn maintenance_can_be_scoped_to_one_exact_authority() {
    let identity = identity(
        GithubServerServiceScope::WorkflowPermissionsRead,
        GithubServerServiceJwtIssuer::AppClientId,
    );
    let selector = GithubServerServiceAuthoritySelector::from_identity(&identity);
    let request = ClaimNextGithubServerServiceMaintenance::for_authority(
        selector.clone(),
        worker(),
        UnixMillis::new(1_000),
        UnixMillis::new(2_000),
    )
    .expect("targeted maintenance request");
    assert_eq!(request.tenant(), identity.tenant());
    assert_eq!(request.authority(), Some(&selector));

    let unscoped = ClaimNextGithubServerServiceMaintenance::new(
        identity.tenant().clone(),
        worker(),
        UnixMillis::new(1_000),
        UnixMillis::new(2_000),
    )
    .expect("tenant maintenance request");
    assert!(unscoped.authority().is_none());
}

#[test]
fn server_service_policies_are_fixed_disjoint_and_digest_bound() {
    let checks = GithubServerServiceScope::ChecksWrite;
    let source = GithubServerServiceScope::RepositoryContentsRead;
    let workflow_permissions = GithubServerServiceScope::WorkflowPermissionsRead;
    let pull_request_files = GithubServerServiceScope::PullRequestsRead;
    assert_eq!(checks.permissions_json(), r#"{"checks":"write"}"#);
    assert!(!checks.permissions_json().contains("contents"));
    assert_eq!(source.permissions_json(), r#"{"contents":"read"}"#);
    assert!(!source.permissions_json().contains("checks"));
    assert_eq!(
        workflow_permissions.permissions_json(),
        r#"{"administration":"read"}"#
    );
    assert!(!workflow_permissions.permissions_json().contains("checks"));
    assert!(!workflow_permissions.permissions_json().contains("contents"));
    assert_ne!(checks.policy_digest(), source.policy_digest());
    assert_ne!(checks.policy_digest(), workflow_permissions.policy_digest());
    assert_ne!(source.policy_digest(), workflow_permissions.policy_digest());
    assert_eq!(
        pull_request_files.permissions_json(),
        r#"{"pull_requests":"read"}"#
    );
    assert!(!pull_request_files.permissions_json().contains("contents"));
    assert_eq!(
        pull_request_files.policy_digest(),
        Sha256Digest::from_bytes([
            0x10, 0xd7, 0x47, 0x93, 0xa5, 0xed, 0x7a, 0xc4, 0x47, 0x68, 0x94, 0xf6, 0x56, 0xa1,
            0x15, 0x76, 0xad, 0xf8, 0xa5, 0x55, 0x59, 0xd0, 0xf0, 0x6a, 0x4e, 0x58, 0x51, 0x96,
            0x3b, 0x17, 0x61, 0x9c,
        ])
    );
    assert_ne!(source.policy_digest(), pull_request_files.policy_digest());
    assert_ne!(
        workflow_permissions.policy_digest(),
        pull_request_files.policy_digest()
    );

    for action in [
        GithubServerServiceAction::EnsureCheckSuite,
        GithubServerServiceAction::CreateCheckRun,
        GithubServerServiceAction::ReconcileCheckRun,
        GithubServerServiceAction::PublishCheckRun,
    ] {
        assert_eq!(action.required_scope(), checks);
    }
    for action in [
        GithubServerServiceAction::FetchRepositoryRevision,
        GithubServerServiceAction::FetchRepositoryChangedFiles,
        GithubServerServiceAction::DiscoverRepositorySchedules,
    ] {
        assert_eq!(action.required_scope(), source);
    }
    assert_eq!(
        GithubServerServiceAction::ObserveWorkflowPermissionDefaults.required_scope(),
        workflow_permissions
    );
    assert_eq!(
        GithubServerServiceAction::FetchPullRequestFiles.required_scope(),
        pull_request_files
    );
}

#[test]
fn exact_jwt_issuer_choice_changes_immutable_identity() {
    let client_issuer = identity(
        GithubServerServiceScope::ChecksWrite,
        GithubServerServiceJwtIssuer::AppClientId,
    );
    let app_id_issuer = identity(
        GithubServerServiceScope::ChecksWrite,
        GithubServerServiceJwtIssuer::AppId,
    );
    assert_ne!(client_issuer, app_id_issuer);
    assert_ne!(
        client_issuer.identity_digest(),
        app_id_issuer.identity_digest()
    );
    assert_eq!(client_issuer.github_app_id().get(), 17);
    assert_eq!(
        client_issuer.app_client_id().as_str(),
        "Iv1.8a61f9b3a7aba766"
    );
    assert!(GithubServerServiceAppClientId::new("Iv1.ab1112223334445c").is_ok());
    assert!(GithubServerServiceAppClientId::new("Iv1.").is_err());
    assert!(GithubRepositoryName::new("a/b").is_ok());
}

#[test]
fn failure_breaker_descriptor_requires_exact_saturated_rearm_shape() {
    let identity = identity(
        GithubServerServiceScope::ChecksWrite,
        GithubServerServiceJwtIssuer::AppClientId,
    );
    let gate = GithubServerServiceGeneration::new(1).expect("gate generation");
    let next = GithubServerServiceGeneration::new(2).expect("next generation");
    let descriptor = GithubServerServiceAuthorityDescriptor::from_durable_parts(
        identity.clone(),
        GithubServerServiceAuthorityState::Active,
        None,
        None,
        next,
        32,
        Some(UnixMillis::new(200)),
        Some(gate),
        Some(UnixMillis::new(86_400_200)),
        UnixMillis::new(100),
        UnixMillis::new(200),
    )
    .expect("saturated descriptor");
    assert_eq!(
        descriptor.failure_budget_rearm_at(),
        Some(UnixMillis::new(86_400_200))
    );
    assert!(
        GithubServerServiceAuthorityDescriptor::from_durable_parts(
            identity.clone(),
            GithubServerServiceAuthorityState::Active,
            None,
            None,
            next,
            32,
            Some(UnixMillis::new(200)),
            Some(gate),
            None,
            UnixMillis::new(100),
            UnixMillis::new(200),
        )
        .is_err()
    );
    assert!(
        GithubServerServiceAuthorityDescriptor::from_durable_parts(
            identity,
            GithubServerServiceAuthorityState::Active,
            None,
            None,
            next,
            31,
            Some(UnixMillis::new(200)),
            Some(gate),
            Some(UnixMillis::new(86_400_200)),
            UnixMillis::new(100),
            UnixMillis::new(200),
        )
        .is_err()
    );
}

#[test]
fn next_maintenance_claim_is_tenant_scoped_and_bounded() {
    let tenant = TenantScope::from_authenticated_tenant_id("tenant").expect("tenant");
    let claim_worker = worker();
    let request = ClaimNextGithubServerServiceMaintenance::new(
        tenant.clone(),
        claim_worker,
        UnixMillis::new(1_000),
        UnixMillis::new(1_100),
    )
    .expect("bounded maintenance claim");
    assert_eq!(request.tenant(), &tenant);
    assert_eq!(request.worker(), claim_worker);
    assert_eq!(request.observed_at(), UnixMillis::new(1_000));
    assert_eq!(request.claim_expires_at(), UnixMillis::new(1_100));
    assert!(matches!(
        ClaimNextGithubServerServiceMaintenance::new(
            tenant.clone(),
            worker(),
            UnixMillis::new(1_000),
            UnixMillis::new(121_001),
        ),
        Err(GithubServerServiceValueError::InvalidTimeInterval)
    ));
    assert!(matches!(
        ClaimNextGithubServerServiceMaintenance::new(
            tenant.clone(),
            worker(),
            UnixMillis::new(1_000),
            UnixMillis::new(1_000),
        ),
        Err(GithubServerServiceValueError::InvalidTimeInterval)
    ));
    assert!(matches!(
        ClaimNextGithubServerServiceMaintenance::new(
            tenant.clone(),
            worker(),
            UnixMillis::new(1_000),
            UnixMillis::new(999),
        ),
        Err(GithubServerServiceValueError::InvalidTimeInterval)
    ));
    assert!(matches!(
        ClaimNextGithubServerServiceMaintenance::new(
            tenant,
            worker(),
            UnixMillis::new(-1),
            UnixMillis::new(1_000),
        ),
        Err(GithubServerServiceValueError::NegativeTimestamp)
    ));
}

#[test]
fn protected_frame_bound_is_exact_and_metadata_authenticates_expiry() {
    let identity = identity(
        GithubServerServiceScope::ChecksWrite,
        GithubServerServiceJwtIssuer::AppClientId,
    );
    let generation = GithubServerServiceGeneration::new(1).expect("generation");
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        identity.clone(),
        generation,
        UnixMillis::new(1_000),
        UnixMillis::new(1_100),
        UnixMillis::new(3_600_000),
        MAX_GITHUB_SERVICE_PLAINTEXT_BYTES,
        Sha256Digest::from_bytes([31; 32]),
    )
    .expect("maximum protected frame");
    assert_eq!(metadata.plaintext_size_bytes(), 16 * 1024);
    assert_eq!(metadata.requested_at(), UnixMillis::new(1_000));
    assert_eq!(metadata.request_deadline(), UnixMillis::new(1_100));
    assert_eq!(metadata.safe_erase_after(), UnixMillis::new(3_720_000));
    assert_eq!(metadata.usable_until(), Some(UnixMillis::new(3_540_000)));
    let shifted_window = GithubServerServiceEnvelopeMetadata::new(
        identity.clone(),
        generation,
        UnixMillis::new(1_001),
        UnixMillis::new(1_101),
        UnixMillis::new(3_600_000),
        MAX_GITHUB_SERVICE_PLAINTEXT_BYTES,
        Sha256Digest::from_bytes([31; 32]),
    )
    .expect("shifted request window");
    assert_ne!(metadata.aad_digest(), shifted_window.aad_digest());

    let envelope = envelope(
        usize::try_from(MAX_GITHUB_SERVICE_PLAINTEXT_BYTES)
            .expect("protected-frame bound fits usize"),
    );
    let protected = ProtectedGithubServerServiceCredential::new(metadata, envelope)
        .expect("matching protected envelope");
    assert_eq!(protected.envelope().ciphertext().len(), 16 * 1024 + 16);

    assert!(matches!(
        GithubServerServiceEnvelopeMetadata::new(
            identity,
            generation,
            UnixMillis::new(1_000),
            UnixMillis::new(1_100),
            UnixMillis::new(3_600_000),
            MAX_GITHUB_SERVICE_PLAINTEXT_BYTES + 1,
            Sha256Digest::from_bytes([31; 32]),
        ),
        Err(GithubServerServiceValueError::InvalidProtectedPayload)
    ));
}

#[test]
fn ready_commit_and_handoff_bind_generation_action_revision_and_horizon() {
    let identity = identity(
        GithubServerServiceScope::ChecksWrite,
        GithubServerServiceJwtIssuer::AppClientId,
    );
    let generation = GithubServerServiceGeneration::new(1).expect("generation");
    let key = GithubServerServiceIssuanceKey::new(identity.authority_id(), generation);
    let claim = GithubServerServiceClaim::from_durable_parts(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        key,
        worker(),
        GithubServerServiceClaimFence::new(1).expect("fence"),
    )
    .expect("claim");
    let protected = protected(identity.clone(), generation, 32);
    assert!(FinishGithubServerServiceMint::ready(claim, protected, UnixMillis::new(1_200)).is_ok());

    let near_expiry = protected_with_expiry(
        identity.clone(),
        generation,
        32,
        UnixMillis::new(1_200 + MIN_GITHUB_SERVICE_READY_USE_MILLIS + 60_000 - 1),
    );
    let near_claim = GithubServerServiceClaim::from_durable_parts(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        key,
        worker(),
        GithubServerServiceClaimFence::new(1).expect("fence"),
    )
    .expect("claim");
    assert!(matches!(
        FinishGithubServerServiceMint::ready(
            near_claim.clone(),
            near_expiry,
            UnixMillis::new(1_200)
        ),
        Err(GithubServerServiceValueError::InvalidCommit)
    ));
    let revoke_only = protected_with_expiry(
        identity.clone(),
        generation,
        32,
        UnixMillis::new(1_200 + MIN_GITHUB_SERVICE_READY_USE_MILLIS + 60_000 - 1),
    );
    assert!(
        FinishGithubServerServiceMint::issued_revoke_only(
            near_claim,
            revoke_only,
            UnixMillis::new(1_200)
        )
        .is_ok()
    );

    assert_unknown_expiry_is_revoke_only(&identity, generation, key);

    let consumer = GithubServerServiceConsumerClaim::new(
        GithubServerServiceConsumerId::from_uuid(Uuid::new_v4()).expect("consumer"),
        worker(),
        GithubServerServiceClaimFence::new(9).expect("consumer fence"),
        GithubServerServiceAction::PublishCheckRun,
        GithubServerServiceRevision::new(4).expect("revision"),
    );
    let handoff = AcquireGithubServerServiceHandoff::new(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        GithubServerServiceHandoffId::from_uuid(Uuid::new_v4()).expect("handoff"),
        consumer,
        UnixMillis::new(2_000),
        UnixMillis::new(2_500),
    )
    .expect("bounded handoff");
    assert_eq!(handoff.consumer(), consumer);
}

fn assert_unknown_expiry_is_revoke_only(
    identity: &GithubServerServiceAuthorityIdentity,
    generation: GithubServerServiceGeneration,
    key: GithubServerServiceIssuanceKey,
) {
    let unknown_expiry = GithubServerServiceEnvelopeMetadata::unknown_provider_expiry(
        identity.clone(),
        generation,
        UnixMillis::new(1_000),
        UnixMillis::new(1_100),
        32,
        Sha256Digest::from_bytes([31; 32]),
    )
    .expect("unknown-expiry revoke-only metadata");
    assert_eq!(unknown_expiry.provider_expires_at(), None);
    assert_eq!(unknown_expiry.usable_until(), None);
    assert_eq!(
        unknown_expiry.safe_erase_after(),
        UnixMillis::new(3_781_100)
    );
    let unknown_ready =
        ProtectedGithubServerServiceCredential::new(unknown_expiry.clone(), envelope(32))
            .expect("protected unknown-expiry token");
    let unknown_ready_claim = GithubServerServiceClaim::from_durable_parts(
        GithubServerServiceAuthoritySelector::from_identity(identity),
        key,
        worker(),
        GithubServerServiceClaimFence::new(1).expect("fence"),
    )
    .expect("claim");
    assert!(matches!(
        FinishGithubServerServiceMint::ready(
            unknown_ready_claim,
            unknown_ready,
            UnixMillis::new(1_200)
        ),
        Err(GithubServerServiceValueError::InvalidCommit)
    ));
    let unknown_revoke_only =
        ProtectedGithubServerServiceCredential::new(unknown_expiry, envelope(32))
            .expect("protected unknown-expiry token");
    let unknown_revoke_claim = GithubServerServiceClaim::from_durable_parts(
        GithubServerServiceAuthoritySelector::from_identity(identity),
        key,
        worker(),
        GithubServerServiceClaimFence::new(1).expect("fence"),
    )
    .expect("claim");
    assert!(
        FinishGithubServerServiceMint::issued_revoke_only(
            unknown_revoke_claim,
            unknown_revoke_only,
            UnixMillis::new(1_200)
        )
        .is_ok()
    );
}

#[test]
fn repository_port_remains_object_safe() {
    fn accepts(_: &dyn GithubServerServiceAuthorityRepository) {}
    let _ = accepts;
}

#[test]
fn handoff_limits_are_action_specific_and_revoke_only_custody_is_never_deliverable() {
    let identity = identity(
        GithubServerServiceScope::ChecksWrite,
        GithubServerServiceJwtIssuer::AppClientId,
    );
    let generation = GithubServerServiceGeneration::new(1).expect("generation");
    let key = GithubServerServiceIssuanceKey::new(identity.authority_id(), generation);
    let handoff_id = GithubServerServiceHandoffId::from_uuid(Uuid::new_v4()).expect("handoff");
    let ensure_consumer = GithubServerServiceConsumerClaim::new(
        GithubServerServiceConsumerId::from_uuid(Uuid::new_v4()).expect("consumer"),
        worker(),
        GithubServerServiceClaimFence::new(1).expect("fence"),
        GithubServerServiceAction::EnsureCheckSuite,
        GithubServerServiceRevision::new(1).expect("revision"),
    );
    let one_request_horizon = 15 * 60 * 1_000 + MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS;
    assert_eq!(
        GithubServerServiceAction::EnsureCheckSuite.provider_tail_millis(),
        MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS
    );
    assert_eq!(
        GithubServerServiceAction::PublishCheckRun.provider_tail_millis(),
        2 * MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS
    );
    assert!(
        AcquireGithubServerServiceHandoff::new(
            GithubServerServiceAuthoritySelector::from_identity(&identity),
            handoff_id,
            ensure_consumer,
            UnixMillis::new(2_000),
            UnixMillis::new(2_000 + one_request_horizon),
        )
        .is_ok()
    );
    assert!(matches!(
        AcquireGithubServerServiceHandoff::new(
            GithubServerServiceAuthoritySelector::from_identity(&identity),
            handoff_id,
            ensure_consumer,
            UnixMillis::new(2_000),
            UnixMillis::new(2_001 + one_request_horizon),
        ),
        Err(GithubServerServiceValueError::InvalidTimeInterval)
    ));

    let publish_consumer = GithubServerServiceConsumerClaim::new(
        GithubServerServiceConsumerId::from_uuid(Uuid::new_v4()).expect("consumer"),
        worker(),
        GithubServerServiceClaimFence::new(1).expect("fence"),
        GithubServerServiceAction::PublishCheckRun,
        GithubServerServiceRevision::new(1).expect("revision"),
    );
    assert!(
        AcquireGithubServerServiceHandoff::new(
            GithubServerServiceAuthoritySelector::from_identity(&identity),
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4()).expect("handoff"),
            publish_consumer,
            UnixMillis::new(2_000),
            UnixMillis::new(2_000 + MAX_GITHUB_SERVICE_HANDOFF_MILLIS),
        )
        .is_ok()
    );

    let revoke_only_receipt = GithubServerServiceIssuanceReceipt::from_durable_parts(
        key,
        GithubServerServiceIssuanceState::RevokePending,
        1,
        0,
        UnixMillis::new(1_000),
        UnixMillis::new(1_100),
        UnixMillis::new(3_781_100),
        Some(UnixMillis::new(3_600_000)),
        UnixMillis::new(3_720_000),
        None,
        UnixMillis::new(1_200),
    )
    .expect("revoke-only receipt");
    assert!(matches!(
        GithubServerServiceCredentialHandoff::from_durable_parts(
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4()).expect("handoff"),
            publish_consumer,
            identity.clone(),
            revoke_only_receipt,
            UnixMillis::new(2_500),
            UnixMillis::new(2_000),
            UnixMillis::new(2_100),
            protected(identity, generation, 32),
        ),
        Err(GithubServerServiceValueError::InvalidHandoff)
    ));
}

fn identity(
    scope: GithubServerServiceScope,
    jwt_issuer: GithubServerServiceJwtIssuer,
) -> GithubServerServiceAuthorityIdentity {
    GithubServerServiceAuthorityIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant").expect("tenant"),
        authority_id(),
        RepositoryId::from_uuid(Uuid::from_u128(0x100)),
        ProviderConnectionId::from_uuid(Uuid::from_u128(0x200)).expect("connection"),
        ProviderInstallationId::new(11).expect("installation"),
        GithubServerServiceAppId::new(17).expect("App"),
        ProviderRepositoryId::new(13).expect("repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        scope,
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("client ID"),
        jwt_issuer,
        Sha256Digest::from_bytes([21; 32]),
        GithubServerServiceRevision::new(5).expect("App revision"),
        GithubServerServiceRevision::new(1).expect("policy revision"),
        Sha256Digest::from_bytes([22; 32]),
    )
    .expect("authority identity")
}

fn protected(
    identity: GithubServerServiceAuthorityIdentity,
    generation: GithubServerServiceGeneration,
    size: u64,
) -> ProtectedGithubServerServiceCredential {
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        identity,
        generation,
        UnixMillis::new(1_000),
        UnixMillis::new(1_100),
        UnixMillis::new(3_600_000),
        size,
        Sha256Digest::from_bytes([31; 32]),
    )
    .expect("metadata");
    ProtectedGithubServerServiceCredential::new(
        metadata,
        envelope(usize::try_from(size).expect("validated test size fits usize")),
    )
    .expect("protected")
}

fn protected_with_expiry(
    identity: GithubServerServiceAuthorityIdentity,
    generation: GithubServerServiceGeneration,
    size: u64,
    provider_expires_at: UnixMillis,
) -> ProtectedGithubServerServiceCredential {
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        identity,
        generation,
        UnixMillis::new(1_000),
        UnixMillis::new(1_100),
        provider_expires_at,
        size,
        Sha256Digest::from_bytes([31; 32]),
    )
    .expect("metadata");
    ProtectedGithubServerServiceCredential::new(
        metadata,
        envelope(usize::try_from(size).expect("validated test size fits usize")),
    )
    .expect("protected")
}

fn envelope(size: usize) -> EncryptedEnvelope {
    EncryptedEnvelope::from_parts(
        1,
        WrappedDataKey::new(KeyId::new("key-a").expect("key ID"), vec![7; 48])
            .expect("wrapped key"),
        [8; 12],
        vec![9; size + 16],
    )
    .expect("envelope")
}

fn authority_id() -> GithubServerServiceAuthorityId {
    GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(0x300)).expect("authority")
}

fn worker() -> GithubServerServiceWorkerId {
    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4()).expect("worker")
}
