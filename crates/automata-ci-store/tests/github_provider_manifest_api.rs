use crate::github_manifest_fixture;

use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_store::{
    BootstrapGithubProviderManifest, GITHUB_PROVIDER_ALL_DIRECT_WORKFLOWS_KEY,
    GITHUB_PROVIDER_ARCHIVE_FORMAT, GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES,
    GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES, GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES,
    GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES, GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES,
    GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS, GITHUB_PROVIDER_ARCHIVE_ORIGIN, GITHUB_PROVIDER_EVENT,
    GITHUB_PROVIDER_GIT_REF, GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES,
    GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS, GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION,
    GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION, GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS,
    GITHUB_PROVIDER_REST_API_VERSION, GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS,
    GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES, GITHUB_PROVIDER_WORKFLOW_MAX_BYTES, GithubCheckName,
    GithubProviderGitRef, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository, GithubProviderManifestRevision,
    GithubProviderManifestValueError, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryName, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, ProviderConnectionId,
    ProviderDeliveryIdentity, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility, TenantScope,
    github_provider_repository_id,
};
use uuid::Uuid;

#[test]
fn manifest_closes_public_repository_selector_and_origins() {
    let manifest = manifest(1, 1, 1, [7; 32], "Automata CI");
    assert_eq!(
        manifest.repository_id(),
        github_provider_repository_id(manifest.tenant(), manifest.github_repository_id())
    );
    assert_eq!(
        manifest.repository_visibility(),
        ProviderRepositoryVisibility::Public
    );
    assert_eq!(
        manifest.workflow_path(),
        GITHUB_PROVIDER_ALL_DIRECT_WORKFLOWS_KEY
    );
    assert_eq!(
        manifest.check_subject_key().as_str(),
        manifest.workflow_path()
    );
    assert_eq!(manifest.event_name(), GITHUB_PROVIDER_EVENT);
    assert_eq!(manifest.git_ref(), GITHUB_PROVIDER_GIT_REF);
    assert_eq!(manifest.origins(), GithubProviderOrigins::github_dot_com());
    assert_eq!(
        manifest.origins().archive_origin(),
        GITHUB_PROVIDER_ARCHIVE_ORIGIN
    );
    assert_eq!(manifest.archive_format(), GITHUB_PROVIDER_ARCHIVE_FORMAT);
    assert_eq!(
        manifest.rest_api_version(),
        GITHUB_PROVIDER_REST_API_VERSION
    );
    assert_eq!(
        manifest.source_authentication(),
        GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION
    );
    assert_eq!(manifest.app_client_id().as_str(), "Iv1.8a61f9b3a7aba766");
    assert_eq!(
        manifest.check_app_id().get(),
        manifest.github_app_id().get()
    );

    let public = delivery_identity(ProviderRepositoryVisibility::Public);
    let private = delivery_identity(ProviderRepositoryVisibility::Private);
    assert!(manifest.matches_delivery_identity(&public));
    assert!(!manifest.matches_delivery_identity(&private));

    let private_manifest = manifest_with(
        2,
        1,
        1,
        2,
        [7; 32],
        [9; 32],
        "Automata CI",
        ProviderRepositoryVisibility::Private,
    );
    assert_eq!(
        private_manifest.repository_visibility(),
        ProviderRepositoryVisibility::Private
    );
    assert_eq!(
        private_manifest.source_authentication(),
        GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION
    );
    assert!(!private_manifest.matches_delivery_identity(&public));
    assert!(private_manifest.matches_delivery_identity(&private));
}

#[test]
fn resource_policy_accepts_only_the_exact_supported_values() {
    let exact = GithubProviderManifestLimits::github_dot_com_ci();
    assert_eq!(
        exact.webhook_max_body_bytes(),
        GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES
    );
    assert_eq!(
        exact.webhook_accept_timeout_millis(),
        GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS
    );
    assert_eq!(
        exact.push_webhook_max_commits(),
        GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS
    );
    assert_eq!(
        exact.path_filter_max_commits(),
        GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS
    );
    assert_eq!(
        exact.path_filter_max_changed_files(),
        GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES
    );
    assert_eq!(
        exact.archive_max_compressed_bytes(),
        GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES
    );
    assert_eq!(
        exact.archive_max_decompressed_bytes(),
        GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES
    );
    assert_eq!(
        exact.archive_max_entries(),
        GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES
    );
    assert_eq!(
        exact.archive_max_expanded_bytes(),
        GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES
    );
    assert_eq!(
        exact.archive_max_entry_path_bytes(),
        GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES
    );
    assert_eq!(
        exact.archive_max_workflows(),
        GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS
    );
    assert_eq!(
        exact.workflow_max_bytes(),
        GITHUB_PROVIDER_WORKFLOW_MAX_BYTES
    );

    assert_eq!(
        GithubProviderManifestLimits::new(
            GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES,
            GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS - 1,
            GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS,
            GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS,
            GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES,
            GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES,
            GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES,
            GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES,
            GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES,
            GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES,
            GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS,
            GITHUB_PROVIDER_WORKFLOW_MAX_BYTES,
        ),
        Err(GithubProviderManifestValueError::InvalidLimits)
    );
    assert_eq!(
        GithubProviderManifestLimits::new(
            GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES,
            GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS,
            GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS,
            GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS,
            GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES,
            GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES - 1,
            GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES,
            GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES,
            GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES,
            GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES,
            GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS,
            GITHUB_PROVIDER_WORKFLOW_MAX_BYTES,
        ),
        Err(GithubProviderManifestValueError::InvalidLimits)
    );
}

#[test]
fn all_direct_selection_is_canonical_and_digest_bound() {
    let all_direct = manifest_with_profile_selection(
        1,
        1,
        1,
        1,
        [7; 32],
        [9; 32],
        "Automata CI",
        ProviderRepositoryVisibility::Public,
        automata_ci_core::JobAuthorityProfile::Standard,
        GithubProviderWorkflowSelection::all_direct(),
    );

    assert_eq!(all_direct.workflow_path(), ".ci/workflows");
    assert!(all_direct.selects_workflow_path(".ci/workflows/build.yml"));
    assert!(all_direct.selects_workflow_path(".ci/workflows/release.yaml"));
    for rejected in [
        ".ci/workflows/nested/build.yml",
        ".ci/workflows/build.yaml/extra",
        ".ci/workflows/build.YML",
        ".ci/workflows",
        "workflows/build.yml",
    ] {
        assert!(!all_direct.selects_workflow_path(rejected), "{rejected}");
    }
}

#[test]
fn configured_default_branch_ref_is_canonical_and_digest_bound() {
    let main = manifest_with_profile_selection_at_ref(
        1,
        1,
        1,
        1,
        [7; 32],
        [9; 32],
        "Automata CI",
        ProviderRepositoryVisibility::Public,
        automata_ci_core::JobAuthorityProfile::Standard,
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
    );
    let release = manifest_with_profile_selection_at_ref(
        1,
        1,
        1,
        1,
        [7; 32],
        [9; 32],
        "Automata CI",
        ProviderRepositoryVisibility::Public,
        automata_ci_core::JobAuthorityProfile::Standard,
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::new("refs/heads/release/stable").expect("branch ref"),
    );
    assert_eq!(release.git_ref(), "refs/heads/release/stable");
    assert_ne!(release.digest(), main.digest());
    assert_eq!(
        GithubProviderGitRef::new("refs/heads/refs/release")
            .expect("nested refs branch")
            .as_str(),
        "refs/heads/refs/release"
    );

    for invalid in [
        "main",
        "refs/tags/release",
        "refs/heads/.hidden",
        "refs/heads/release..stable",
        "refs/heads/release.lock",
        "refs/heads/release stable",
    ] {
        assert_eq!(
            GithubProviderGitRef::new(invalid),
            Err(GithubProviderManifestValueError::InvalidGitRef),
            "{invalid}"
        );
    }
}

#[test]
fn digest_binds_every_mutable_evidence_and_server_derived_repository() {
    let original = manifest(1, 1, 1, [7; 32], "Automata CI");
    let exact_reconstruction = manifest(1, 1, 1, [7; 32], "Automata CI");
    let rotated_key = manifest(2, 2, 1, [8; 32], "Automata CI");
    let renamed_check = manifest(2, 1, 2, [7; 32], "Automata CI / main");
    let rotated_verifier = manifest_with(
        2,
        1,
        2,
        1,
        [7; 32],
        [10; 32],
        "Automata CI",
        ProviderRepositoryVisibility::Public,
    );
    let credential_free = manifest_with_profile(
        1,
        1,
        1,
        1,
        [7; 32],
        [9; 32],
        "Automata CI",
        ProviderRepositoryVisibility::Public,
        automata_ci_core::JobAuthorityProfile::CredentialFree,
    );
    assert_eq!(original, exact_reconstruction);
    assert_eq!(original.digest(), exact_reconstruction.digest());
    assert_eq!(
        original.repository_id().as_uuid().to_string(),
        "93b978d6-eb38-83ec-a919-cfb0b977ca8a"
    );
    assert_eq!(
        original.digest().to_string(),
        "20f16f866564dd2c9ab17776c2f8acabc5c619fa305066b0f86c1ec9b82c1b64"
    );
    assert_eq!(
        credential_free.authority_profile(),
        automata_ci_core::JobAuthorityProfile::CredentialFree
    );
    assert_ne!(original.digest(), credential_free.digest());
    assert_ne!(original.digest(), rotated_key.digest());
    assert_ne!(original.digest(), renamed_check.digest());
    assert_ne!(original.digest(), rotated_verifier.digest());
    assert_ne!(rotated_key.digest(), renamed_check.digest());

    assert_eq!(
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([0; 32])),
        Err(GithubProviderManifestValueError::InvalidWebhookVerifierFingerprint)
    );

    let other_tenant = TenantScope::from_authenticated_tenant_id("other").expect("tenant");
    assert_ne!(
        original.repository_id(),
        github_provider_repository_id(&other_tenant, original.github_repository_id())
    );
}

#[test]
fn owner_binding_uses_an_independent_domain_and_preserves_the_base_digest() {
    let base = manifest(1, 1, 1, [7; 32], "Automata CI");
    let owner = base
        .clone()
        .with_repository_owner_id(ProviderRepositoryOwnerId::new(404).expect("owner ID"));
    let other_owner = base
        .clone()
        .with_repository_owner_id(ProviderRepositoryOwnerId::new(405).expect("owner ID"));

    assert_eq!(base.github_repository_owner_id(), None);
    assert_eq!(
        owner.github_repository_owner_id(),
        Some(ProviderRepositoryOwnerId::new(404).expect("owner ID"))
    );
    assert_ne!(base.digest(), owner.digest());
    assert_ne!(owner.digest(), other_owner.digest());
    assert_eq!(
        base.digest().to_string(),
        "20f16f866564dd2c9ab17776c2f8acabc5c619fa305066b0f86c1ec9b82c1b64"
    );
}

#[test]
fn canonical_repository_bounds_include_one_character_owner() {
    let repository = GithubRepositoryName::new("a/r").expect("minimum canonical repository");
    assert_eq!(repository.as_str(), "a/r");
    assert!(GithubRepositoryName::new("a--b/repository").is_err());
    assert!(GithubRepositoryName::new("owner/.git").is_err());
    assert!(GithubRepositoryName::new("owner/repository/extra").is_err());
}

fn accepts_manifest_repository(_: &dyn GithubProviderManifestRepository) {}

#[test]
fn bootstrap_request_is_nonnegative_and_port_is_object_safe() {
    let desired = manifest(1, 1, 1, [7; 32], "Automata CI");
    let request = BootstrapGithubProviderManifest::new(desired.clone(), UnixMillis::new(100))
        .expect("bootstrap request");
    assert_eq!(request.manifest(), &desired);
    assert_eq!(request.applied_at(), UnixMillis::new(100));
    assert!(matches!(
        BootstrapGithubProviderManifest::new(desired, UnixMillis::new(-1)),
        Err(GithubProviderManifestValueError::NegativeTimestamp)
    ));

    let _ = accepts_manifest_repository;
}

fn manifest(
    manifest_revision: u64,
    app_revision: u64,
    policy_revision: u64,
    spki: [u8; 32],
    check_name: &str,
) -> GithubProviderManifest {
    manifest_with(
        manifest_revision,
        app_revision,
        1,
        policy_revision,
        spki,
        [9; 32],
        check_name,
        ProviderRepositoryVisibility::Public,
    )
}

#[allow(clippy::too_many_arguments)]
fn manifest_with(
    manifest_revision: u64,
    app_revision: u64,
    webhook_verifier_revision: u64,
    policy_revision: u64,
    spki: [u8; 32],
    webhook_verifier_fingerprint: [u8; 32],
    check_name: &str,
    visibility: ProviderRepositoryVisibility,
) -> GithubProviderManifest {
    manifest_with_profile(
        manifest_revision,
        app_revision,
        webhook_verifier_revision,
        policy_revision,
        spki,
        webhook_verifier_fingerprint,
        check_name,
        visibility,
        automata_ci_core::JobAuthorityProfile::Standard,
    )
}

#[allow(clippy::too_many_arguments)]
fn manifest_with_profile(
    manifest_revision: u64,
    app_revision: u64,
    webhook_verifier_revision: u64,
    policy_revision: u64,
    spki: [u8; 32],
    webhook_verifier_fingerprint: [u8; 32],
    check_name: &str,
    visibility: ProviderRepositoryVisibility,
    authority_profile: automata_ci_core::JobAuthorityProfile,
) -> GithubProviderManifest {
    manifest_with_profile_selection(
        manifest_revision,
        app_revision,
        webhook_verifier_revision,
        policy_revision,
        spki,
        webhook_verifier_fingerprint,
        check_name,
        visibility,
        authority_profile,
        GithubProviderWorkflowSelection::all_direct(),
    )
}

#[allow(clippy::too_many_arguments)]
fn manifest_with_profile_selection(
    manifest_revision: u64,
    app_revision: u64,
    webhook_verifier_revision: u64,
    policy_revision: u64,
    spki: [u8; 32],
    webhook_verifier_fingerprint: [u8; 32],
    check_name: &str,
    visibility: ProviderRepositoryVisibility,
    authority_profile: automata_ci_core::JobAuthorityProfile,
    workflow_selection: GithubProviderWorkflowSelection,
) -> GithubProviderManifest {
    manifest_with_profile_selection_at_ref(
        manifest_revision,
        app_revision,
        webhook_verifier_revision,
        policy_revision,
        spki,
        webhook_verifier_fingerprint,
        check_name,
        visibility,
        authority_profile,
        workflow_selection,
        GithubProviderGitRef::main(),
    )
}

#[allow(clippy::too_many_arguments)]
fn manifest_with_profile_selection_at_ref(
    manifest_revision: u64,
    app_revision: u64,
    webhook_verifier_revision: u64,
    policy_revision: u64,
    spki: [u8; 32],
    webhook_verifier_fingerprint: [u8; 32],
    check_name: &str,
    visibility: ProviderRepositoryVisibility,
    authority_profile: automata_ci_core::JobAuthorityProfile,
    workflow_selection: GithubProviderWorkflowSelection,
    git_ref: GithubProviderGitRef,
) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(policy_revision);
    GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        TenantScope::from_authenticated_tenant_id("automata-ci").expect("tenant"),
        ProviderConnectionId::from_uuid(Uuid::from_u128(0x100)).expect("connection"),
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryId::new(202).expect("repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        visibility,
        GithubServerServiceAppId::new(303).expect("App"),
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes(spki),
        GithubServerServiceRevision::new(app_revision).expect("App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes(
            webhook_verifier_fingerprint,
        ))
        .expect("verifier fingerprint"),
        GithubServerServiceRevision::new(webhook_verifier_revision).expect("verifier revision"),
        GithubServerServiceRevision::new(policy_revision).expect("policy revision"),
        authority_profile,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        workflow_selection,
        git_ref,
        GithubCheckName::new(check_name).expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(manifest_revision).expect("manifest revision"),
    )
}

fn delivery_identity(visibility: ProviderRepositoryVisibility) -> ProviderDeliveryIdentity {
    ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("automata-ci").expect("tenant"),
        "github",
        ProviderConnectionId::from_uuid(Uuid::from_u128(0x100)).expect("connection"),
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(202).expect("repository"),
            visibility,
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        "delivery-1",
    )
    .expect("delivery identity")
}
