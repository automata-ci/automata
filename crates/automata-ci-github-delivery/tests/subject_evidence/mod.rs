use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_store::{
    AdmissionObject, GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, GithubAuthenticatedEvent,
    GithubAuthenticatedEventKind, GithubCheckHeadSha, GithubCheckName, GithubCheckSubjectId,
    GithubProviderGitRef, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRevision, GithubProviderOrigins, GithubProviderRunnerPolicyObject,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryName, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision,
    ManifestPinnedGithubDeliveryEvidence, ObjectKey, ProviderDeliveryId, ProviderDeliveryIdentity,
    ProviderRepositoryOwnerId, WorkflowRuntimePolicy, WorkflowRuntimePolicyRevision,
};
use uuid::Uuid;

const FIXTURE_AFTER: &str = "0123456789abcdef0123456789abcdef01234567";
const FIXTURE_RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

pub struct FixtureGithubRuntimePolicy {
    pub runner_policy: GithubProviderRunnerPolicyObject,
    pub revision: WorkflowRuntimePolicyRevision,
    pub semantic_digest: Sha256Digest,
}

pub fn fixture_github_runtime_policy(revision: u64) -> FixtureGithubRuntimePolicy {
    let policy = WorkflowRuntimePolicy::decode_configuration(FIXTURE_RUNTIME_POLICY)
        .expect("fixture runtime policy");
    let canonical = policy.canonical_bytes().expect("canonical runtime policy");
    let object_digest = policy.canonical_digest();
    let object = AdmissionObject::new(
        object_digest,
        ObjectKey::new(format!("github/runner-policy/v1/{object_digest}.json"))
            .expect("runner-policy object key"),
        u64::try_from(canonical.len()).expect("runner-policy size"),
        GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
    )
    .expect("runner-policy object");
    FixtureGithubRuntimePolicy {
        runner_policy: GithubProviderRunnerPolicyObject::new(object)
            .expect("runner-policy descriptor"),
        revision: WorkflowRuntimePolicyRevision::new(revision).expect("runtime-policy revision"),
        semantic_digest: policy.digest(),
    }
}

/// Builds manifest-pinned delivery evidence with the fixed integration-test head.
///
/// # Panics
///
/// Panics when a fixed test identity, manifest field, or authority selector
/// violates the production value contract.
pub fn fixture_subject_evidence(
    delivery_id: ProviderDeliveryId,
    identity: &ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
    accepted_at: UnixMillis,
    seed: u128,
) -> ManifestPinnedGithubDeliveryEvidence {
    fixture_subject_evidence_with_head(
        delivery_id,
        identity,
        repository_owner_id,
        accepted_at,
        seed,
        fixture_check_head_sha(FIXTURE_AFTER),
    )
}

/// Builds manifest-pinned delivery evidence for integration-test fixtures.
///
/// # Panics
///
/// Panics when a fixed test identity, revision, manifest field, or authority
/// selector violates the production value contract.
pub fn fixture_subject_evidence_with_head(
    delivery_id: ProviderDeliveryId,
    identity: &ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
    accepted_at: UnixMillis,
    seed: u128,
    check_head_sha: GithubCheckHeadSha,
) -> ManifestPinnedGithubDeliveryEvidence {
    fixture_subject_evidence_with_selection_and_head(
        delivery_id,
        identity,
        repository_owner_id,
        accepted_at,
        seed,
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
        check_head_sha,
    )
}

/// Builds all-direct manifest-pinned evidence for worker fan-out tests.
pub fn fixture_all_direct_subject_evidence(
    delivery_id: ProviderDeliveryId,
    identity: &ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
    accepted_at: UnixMillis,
    seed: u128,
    git_ref: GithubProviderGitRef,
) -> ManifestPinnedGithubDeliveryEvidence {
    fixture_subject_evidence_with_selection_and_head(
        delivery_id,
        identity,
        repository_owner_id,
        accepted_at,
        seed,
        GithubProviderWorkflowSelection::all_direct(),
        git_ref,
        fixture_check_head_sha(FIXTURE_AFTER),
    )
}

#[allow(clippy::too_many_arguments)]
fn fixture_subject_evidence_with_selection_and_head(
    delivery_id: ProviderDeliveryId,
    identity: &ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
    accepted_at: UnixMillis,
    seed: u128,
    workflow_selection: GithubProviderWorkflowSelection,
    git_ref: GithubProviderGitRef,
    check_head_sha: GithubCheckHeadSha,
) -> ManifestPinnedGithubDeliveryEvidence {
    let authenticated_git_ref = git_ref.as_str().to_owned();
    let app_revision = GithubServerServiceRevision::new(1).expect("App revision");
    let policy_revision = GithubServerServiceRevision::new(1).expect("policy revision");
    let webhook_fingerprint =
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([0x42; 32]))
            .expect("webhook verifier fingerprint");
    let webhook_revision = GithubServerServiceRevision::new(1).expect("webhook revision");
    let runtime_policy = fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        identity.tenant().clone(),
        identity.connection_id(),
        identity.installation_id(),
        identity.repository_id(),
        GithubRepositoryName::new(identity.repository_identity().to_owned())
            .expect("repository name"),
        identity.repository_visibility(),
        GithubServerServiceAppId::new(1).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.fixture").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x41; 32]),
        app_revision,
        webhook_fingerprint,
        webhook_revision,
        policy_revision,
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        workflow_selection,
        git_ref,
        GithubCheckName::new("Automata CI").expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1).expect("manifest revision"),
    );
    let checks_authority = GithubServerServiceAuthoritySelector::from_durable_parts(
        identity.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(seed))
            .expect("checks authority ID"),
        Sha256Digest::from_bytes([0x51; 32]),
        app_revision,
        policy_revision,
    );
    let private_source_authority = (identity.repository_visibility()
        == automata_ci_store::ProviderRepositoryVisibility::Private)
        .then(|| {
            GithubServerServiceAuthoritySelector::from_durable_parts(
                identity.tenant().clone(),
                GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(seed + 1))
                    .expect("private-source authority ID"),
                Sha256Digest::from_bytes([0x52; 32]),
                app_revision,
                policy_revision,
            )
        });
    ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
        delivery_id,
        repository_owner_id,
        manifest,
        webhook_fingerprint,
        webhook_revision,
        checks_authority,
        private_source_authority,
        GithubCheckSubjectId::from_uuid(Uuid::from_u128(seed + 2)).expect("Check subject ID"),
        check_head_sha,
        GithubAuthenticatedEvent::new(GithubAuthenticatedEventKind::Push, authenticated_git_ref)
            .expect("authenticated event"),
        accepted_at,
    )
    .expect("fixture subject evidence")
}

/// Parses one exact lowercase SHA-1 fixture value.
///
/// # Panics
///
/// Panics when the test fixture is not exactly 40 lowercase hexadecimal bytes.
pub fn fixture_check_head_sha(value: &str) -> GithubCheckHeadSha {
    let bytes = value.as_bytes();
    assert_eq!(bytes.len(), 40, "fixture head is an exact SHA-1 hex string");
    let mut decoded = [0_u8; 20];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        decoded[index] = (fixture_hex_nibble(pair[0]) << 4) | fixture_hex_nibble(pair[1]);
    }
    GithubCheckHeadSha::new(decoded).expect("fixture head SHA")
}

fn fixture_hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture head uses lowercase hexadecimal"),
    }
}
