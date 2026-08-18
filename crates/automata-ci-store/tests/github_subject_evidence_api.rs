use crate::github_manifest_fixture;

use automata_ci_core::{GitObjectId, RunId, Sha256Digest, UnixMillis, WorkflowId};
use automata_ci_provider::ProviderConnectionId;
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AdmissionObject,
    AuthenticatedGithubDeliveryClaim, GithubAuthenticatedEvent, GithubAuthenticatedEventKind,
    GithubCheckName, GithubCheckSubjectId, GithubCheckSubjectKey, GithubProviderManifest,
    GithubProviderManifestLimits, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryDispatchEvidenceRepository,
    GithubRepositoryDispatchResolution, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubSubjectEvidenceRepository,
    GithubSubjectEvidenceStoreError, GithubSubjectEvidenceValueError,
    GithubWorkflowRunSubjectEvidence, LogicalWorkflowInvocationId,
    ManifestPinnedGithubDeliveryEvidence, ManifestPinnedGithubDeliveryReceipt, ObjectKey,
    PendingGithubRepositoryDispatchEvidence, ProviderDeliveryClaimFence,
    ProviderDeliveryEventEnvelope, ProviderDeliveryId, ProviderDeliveryIdentity,
    ProviderInstallationId, ProviderProcessingWorkerId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    RecordGithubWorkflowRunSubjectEvidence, RepositoryId, ResolveGithubRepositoryDispatch,
    TenantScope, WorkflowSnapshotId,
};
use uuid::Uuid;

fn delivery(provider: &str) -> AcceptProviderDelivery {
    let identity = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("signed-owner-api").expect("tenant"),
        provider,
        ProviderConnectionId::from_uuid(Uuid::from_u128(0x101)).expect("connection"),
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(202).expect("repository"),
            ProviderRepositoryVisibility::Private,
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        "delivery-api-1",
    )
    .expect("delivery identity");
    AcceptProviderDelivery::new(
        identity,
        Sha256Digest::from_bytes([3; 32]),
        AdmissionObject::new_event(
            Sha256Digest::from_bytes([4; 32]),
            ObjectKey::new("github/events/delivery-api-1").expect("object key"),
            512,
            "application/vnd.automata.github-authenticated-event+json",
        )
        .expect("event object"),
        ProviderDeliveryEventEnvelope::new(
            1,
            1,
            Sha256Digest::from_bytes([5; 32]),
            br#"{"schema":1}"#.to_vec(),
            "application/vnd.automata.provider-event-envelope.v1+json",
        )
        .expect("event envelope"),
        UnixMillis::new(100),
    )
    .expect("delivery")
}

fn push_event() -> GithubAuthenticatedEvent {
    GithubAuthenticatedEvent::new(GithubAuthenticatedEventKind::Push, "refs/heads/main")
        .expect("push event")
}

fn pull_request_event() -> GithubAuthenticatedEvent {
    GithubAuthenticatedEvent::new(
        GithubAuthenticatedEventKind::PullRequest,
        "refs/pull/7/merge",
    )
    .expect("pull-request event")
}

#[test]
fn github_acceptance_compares_signed_and_configured_owner_outside_generic_identity() {
    let owner = ProviderRepositoryOwnerId::new(404).expect("owner");
    let other_owner = ProviderRepositoryOwnerId::new(405).expect("other owner");
    let head = GitObjectId::from_durable_bytes(&[9; 20]).expect("head SHA");
    let verifier =
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([6; 32]))
            .expect("verifier fingerprint");
    let verifier_revision = GithubServerServiceRevision::new(1).expect("verifier revision");
    let request = AcceptManifestPinnedGithubDelivery::new(
        delivery("github"),
        owner,
        owner,
        push_event(),
        head,
        verifier,
        verifier_revision,
    )
    .expect("GitHub request");
    assert_eq!(request.delivery().identity().provider(), "github");
    assert_eq!(request.repository_owner_id(), owner);
    assert_eq!(request.head_sha(), head);
    assert_eq!(
        request.authenticated_webhook_verifier_fingerprint(),
        verifier
    );
    assert_eq!(
        request.authenticated_webhook_verifier_revision(),
        verifier_revision
    );
    assert_eq!(
        format!("{request:?}"),
        "AcceptManifestPinnedGithubDelivery([REDACTED])"
    );

    assert!(matches!(
        AcceptManifestPinnedGithubDelivery::new(
            delivery("github"),
            owner,
            other_owner,
            push_event(),
            head,
            verifier,
            verifier_revision
        ),
        Err(GithubSubjectEvidenceValueError::RepositoryOwnerMismatch)
    ));
    assert!(matches!(
        AcceptManifestPinnedGithubDelivery::new(
            delivery("synthetic"),
            owner,
            owner,
            push_event(),
            head,
            verifier,
            verifier_revision
        ),
        Err(GithubSubjectEvidenceValueError::NotGithub)
    ));
}

#[test]
fn run_receipt_request_binds_every_epoch_four_admission_coordinate() {
    let tenant = TenantScope::from_authenticated_tenant_id("signed-owner-run").expect("tenant");
    let repository_id = RepositoryId::from_uuid(Uuid::from_u128(0x201));
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(0x202));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(0x203));
    let run_id = RunId::from_uuid(Uuid::from_u128(0x204));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(0x205)).expect("invocation");
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(0x206)).expect("delivery");
    let request = RecordGithubWorkflowRunSubjectEvidence::new(
        tenant.clone(),
        repository_id,
        workflow_id,
        snapshot_id,
        run_id,
        invocation_id,
        delivery_id,
        "provider-delivery:api-run",
        admission_claim(delivery_id, 400, 600),
        GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
        GithubCheckSubjectKey::new(".ci/workflows/ci.yml").expect("path"),
        Sha256Digest::from_bytes([1; 32]),
        "push",
        Sha256Digest::from_bytes([2; 32]),
        "refs/heads/main",
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
        UnixMillis::new(500),
    )
    .expect("run receipt request");
    assert_eq!(request.tenant(), &tenant);
    assert_eq!(request.repository_id(), repository_id);
    assert_eq!(request.workflow_id(), workflow_id);
    assert_eq!(request.snapshot_id(), snapshot_id);
    assert_eq!(request.run_id(), run_id);
    assert_eq!(request.root_invocation_id(), invocation_id);
    assert_eq!(request.delivery_id(), delivery_id);
    assert_eq!(request.plan_schema(), 1);
    assert_eq!(request.admitted_at(), UnixMillis::new(500));
    assert_eq!(
        format!("{request:?}"),
        "RecordGithubWorkflowRunSubjectEvidence([REDACTED])"
    );

    assert!(matches!(
        RecordGithubWorkflowRunSubjectEvidence::new(
            tenant,
            RepositoryId::from_uuid(Uuid::nil()),
            workflow_id,
            snapshot_id,
            run_id,
            invocation_id,
            delivery_id,
            "provider-delivery:api-run",
            admission_claim(delivery_id, 400, 600),
            GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
            GithubCheckSubjectKey::new(".ci/workflows/ci.yml").expect("path"),
            Sha256Digest::from_bytes([1; 32]),
            "push",
            Sha256Digest::from_bytes([2; 32]),
            "refs/heads/main",
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
            UnixMillis::new(500),
        ),
        Err(GithubSubjectEvidenceValueError::NilUuid(_))
    ));
}

fn accepts_repository(_: &dyn GithubSubjectEvidenceRepository) {}
fn accepts_repository_dispatch(_: &dyn GithubRepositoryDispatchEvidenceRepository) {}

#[test]
fn repository_ports_are_object_safe_and_errors_are_value_free() {
    let _ = accepts_repository;
    let _ = accepts_repository_dispatch;
    for error in [
        GithubSubjectEvidenceStoreError::AuthorityRejected,
        GithubSubjectEvidenceStoreError::ReplayConflict,
        GithubSubjectEvidenceStoreError::NotFound,
        GithubSubjectEvidenceStoreError::CorruptData,
    ] {
        let rendered = error.to_string();
        assert!(!rendered.contains("automata-ci"));
        assert!(!rendered.contains("delivery-api"));
        assert!(!rendered.contains("github/events"));
    }
}

#[test]
fn repository_dispatch_resolution_is_claim_bound_and_redacted() {
    let manifest = manifest(ProviderRepositoryVisibility::Private);
    let checks = selector(&manifest, 0x401, [7; 32]);
    let private = selector(&manifest, 0x402, [8; 32]);
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(0x403)).expect("delivery");
    let pending = PendingGithubRepositoryDispatchEvidence::from_durable_parts(
        delivery_id,
        ProviderRepositoryOwnerId::new(404).expect("owner"),
        manifest.clone(),
        manifest.webhook_verifier_fingerprint(),
        manifest.webhook_verifier_revision(),
        checks,
        private,
        GithubAuthenticatedEvent::new(
            GithubAuthenticatedEventKind::RepositoryDispatch,
            "refs/heads/main",
        )
        .expect("dispatch event"),
        UnixMillis::new(100),
    )
    .expect("pending dispatch");
    let head = GitObjectId::from_durable_bytes(&[9; 20]).expect("head");
    let resolution = GithubRepositoryDispatchResolution::new(head);
    let request = ResolveGithubRepositoryDispatch::new(
        pending.clone(),
        admission_claim(delivery_id, 100, 300),
        resolution,
        UnixMillis::new(200),
    )
    .expect("private resolution");
    assert_eq!(request.pending(), &pending);
    assert_eq!(request.resolution(), resolution);
    assert_eq!(
        format!("{request:?}"),
        "ResolveGithubRepositoryDispatch([REDACTED])"
    );
    assert!(!format!("{pending:?}").contains("refs/heads/main"));

    assert!(
        ResolveGithubRepositoryDispatch::new(
            pending,
            admission_claim(delivery_id, 100, 300),
            GithubRepositoryDispatchResolution::new(head),
            UnixMillis::new(301),
        )
        .is_err()
    );
}

#[test]
fn public_checked_rehydration_retains_manifest_authorities_check_and_run_evidence() {
    let manifest = manifest(ProviderRepositoryVisibility::Private);
    let checks = selector(&manifest, 0x301, [7; 32]);
    let private = selector(&manifest, 0x302, [8; 32]);
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(0x303)).expect("delivery");
    let subject_id = GithubCheckSubjectId::from_uuid(Uuid::from_u128(0x304)).expect("subject");
    let evidence = ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
        delivery_id,
        ProviderRepositoryOwnerId::new(404).expect("owner"),
        manifest.clone(),
        manifest.webhook_verifier_fingerprint(),
        manifest.webhook_verifier_revision(),
        checks.clone(),
        private.clone(),
        subject_id,
        GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
        push_event(),
        UnixMillis::new(100),
    )
    .expect("delivery evidence");
    assert_eq!(evidence.manifest(), &manifest);
    assert_eq!(evidence.checks_authority(), &checks);
    assert_eq!(evidence.repository_contents_authority(), &private);
    assert_eq!(evidence.check_subject_id(), subject_id);
    let receipt = ManifestPinnedGithubDeliveryReceipt::from_durable_parts(evidence.clone());
    assert_eq!(receipt.evidence(), &evidence);
    assert_eq!(receipt.check_subject_id(), subject_id);

    let request = run_request(&manifest, delivery_id);
    let run_id = request.run_id();
    let run_evidence = GithubWorkflowRunSubjectEvidence::from_durable_parts(
        request,
        subject_id,
        Sha256Digest::from_bytes([9; 32]),
    );
    assert_eq!(run_evidence.run_id(), run_id);
    assert_eq!(run_evidence.delivery_id(), delivery_id);
    assert_eq!(
        format!("{run_evidence:?}"),
        "GithubWorkflowRunSubjectEvidence([REDACTED])"
    );

    assert!(matches!(
        ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
            delivery_id,
            ProviderRepositoryOwnerId::new(404).expect("owner"),
            manifest.clone(),
            GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes(
                [0x66; 32]
            ))
            .expect("different verifier"),
            manifest.webhook_verifier_revision(),
            checks.clone(),
            private.clone(),
            subject_id,
            GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
            push_event(),
            UnixMillis::new(100),
        ),
        Err(GithubSubjectEvidenceValueError::WebhookVerifierPinMismatch)
    ));

    assert!(matches!(
        ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
            delivery_id,
            ProviderRepositoryOwnerId::new(404).expect("owner"),
            manifest.clone(),
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
            checks.clone(),
            checks.clone(),
            subject_id,
            GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
            push_event(),
            UnixMillis::new(100),
        ),
        Err(GithubSubjectEvidenceValueError::AuthorityPinMismatch)
    ));
}

#[test]
fn pull_request_evidence_requires_a_distinct_exact_pull_requests_selector() {
    for visibility in [
        ProviderRepositoryVisibility::Public,
        ProviderRepositoryVisibility::Private,
    ] {
        let manifest = manifest(visibility);
        let checks = selector(&manifest, 0x401, [0x41; 32]);
        let source = selector(&manifest, 0x402, [0x42; 32]);
        let pull_request_files = selector(&manifest, 0x403, [0x43; 32]);
        let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(0x404)).expect("delivery");
        let subject_id = GithubCheckSubjectId::from_uuid(Uuid::from_u128(0x405)).expect("subject");

        let evidence =
            ManifestPinnedGithubDeliveryEvidence::from_durable_parts_with_pull_requests_authority(
                delivery_id,
                ProviderRepositoryOwnerId::new(404).expect("owner"),
                manifest.clone(),
                manifest.webhook_verifier_fingerprint(),
                manifest.webhook_verifier_revision(),
                checks.clone(),
                source.clone(),
                Some(pull_request_files.clone()),
                subject_id,
                GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
                pull_request_event(),
                UnixMillis::new(100),
            )
            .expect("pull-request evidence");
        assert_eq!(
            evidence.pull_requests_authority(),
            Some(&pull_request_files)
        );

        assert!(matches!(
            ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
                delivery_id,
                ProviderRepositoryOwnerId::new(404).expect("owner"),
                manifest.clone(),
                manifest.webhook_verifier_fingerprint(),
                manifest.webhook_verifier_revision(),
                checks.clone(),
                source.clone(),
                subject_id,
                GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
                pull_request_event(),
                UnixMillis::new(100),
            ),
            Err(GithubSubjectEvidenceValueError::AuthorityPinMismatch)
        ));
        assert!(matches!(
            ManifestPinnedGithubDeliveryEvidence::from_durable_parts_with_pull_requests_authority(
                delivery_id,
                ProviderRepositoryOwnerId::new(404).expect("owner"),
                manifest,
                evidence.authenticated_webhook_verifier_fingerprint(),
                evidence.authenticated_webhook_verifier_revision(),
                checks,
                source.clone(),
                Some(source),
                subject_id,
                GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
                pull_request_event(),
                UnixMillis::new(100),
            ),
            Err(GithubSubjectEvidenceValueError::AuthorityPinMismatch)
        ));
    }
}

fn manifest(visibility: ProviderRepositoryVisibility) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    GithubProviderManifest::new(
        TenantScope::from_authenticated_tenant_id("external-adapter").expect("tenant"),
        ProviderConnectionId::from_uuid(Uuid::from_u128(0x311)).expect("connection"),
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryId::new(202).expect("repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        visibility,
        GithubServerServiceAppId::new(303).expect("App"),
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("client"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([5; 32]),
        GithubServerServiceRevision::new(1).expect("app revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([6; 32]))
            .expect("verifier"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
        GithubServerServiceRevision::new(1).expect("policy revision"),
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI").expect("check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1).expect("manifest revision"),
    )
}

fn selector(
    manifest: &GithubProviderManifest,
    id: u128,
    digest: [u8; 32],
) -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_durable_parts(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(id)).expect("authority"),
        Sha256Digest::from_bytes(digest),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
    )
}

fn run_request(
    manifest: &GithubProviderManifest,
    delivery_id: ProviderDeliveryId,
) -> RecordGithubWorkflowRunSubjectEvidence {
    RecordGithubWorkflowRunSubjectEvidence::new(
        manifest.tenant().clone(),
        manifest.repository_id(),
        WorkflowId::from_uuid(Uuid::from_u128(0x321)),
        WorkflowSnapshotId::from_uuid(Uuid::from_u128(0x322)),
        RunId::from_uuid(Uuid::from_u128(0x323)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(0x324)).expect("invocation"),
        delivery_id,
        "provider-delivery:external-adapter",
        admission_claim(delivery_id, 100, 300),
        GitObjectId::from_durable_bytes(&[9; 20]).expect("head"),
        GithubCheckSubjectKey::new(manifest.workflow_path()).expect("path"),
        Sha256Digest::from_bytes([1; 32]),
        manifest.event_name(),
        Sha256Digest::from_bytes([2; 32]),
        manifest.git_ref(),
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
        UnixMillis::new(200),
    )
    .expect("run request")
}

fn admission_claim(
    delivery_id: ProviderDeliveryId,
    claimed_at: i64,
    expires_at: i64,
) -> AuthenticatedGithubDeliveryClaim {
    AuthenticatedGithubDeliveryClaim::new(
        ProviderDeliveryClaimFence::from_durable_parts(
            delivery_id,
            ProviderProcessingWorkerId::from_uuid(Uuid::from_u128(0x401)).expect("claim owner"),
            1,
        )
        .expect("claim fence"),
        1,
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
    )
    .expect("admission claim")
}
