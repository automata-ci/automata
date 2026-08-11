use automata_ci_core::Sha256Digest;
use automata_ci_store::{
    AdmissionObject, BootstrapGithubProviderManifest, BootstrapGithubProviderRepository,
    GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, GithubProviderManifest,
    GithubProviderRunnerPolicyObject, ObjectKey, RegisterWorkflowRuntimePolicy,
    WorkflowRuntimePolicy, WorkflowRuntimePolicyRevision,
};

const FIXTURE_RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

#[derive(Debug)]
pub struct FixtureGithubRuntimePolicy {
    pub runner_policy: GithubProviderRunnerPolicyObject,
    pub revision: WorkflowRuntimePolicyRevision,
    pub semantic_digest: Sha256Digest,
}

/// Builds one internally consistent current runtime-policy fixture.
///
/// # Panics
///
/// Panics only if the checked-in fixture or the requested positive revision
/// violates the current runtime-policy and object-key contracts.
pub fn fixture_github_runtime_policy(revision: u64) -> FixtureGithubRuntimePolicy {
    let policy = fixture_workflow_runtime_policy(revision);
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

#[allow(dead_code)]
/// Builds one exact aggregate repository bootstrap fixture.
///
/// # Panics
///
/// Panics if the supplied manifest disagrees with its runtime-policy revision
/// or if either half violates the current aggregate bootstrap contract.
pub fn fixture_github_repository_bootstrap(
    manifest: GithubProviderManifest,
    applied_at: automata_ci_core::UnixMillis,
) -> BootstrapGithubProviderRepository {
    let runtime_policy = fixture_github_runtime_policy(manifest.runtime_policy_revision().get());
    let policy = fixture_workflow_runtime_policy(manifest.runtime_policy_revision().get());
    assert_eq!(
        runtime_policy.semantic_digest,
        manifest.runtime_policy_digest()
    );
    assert_eq!(&runtime_policy.runner_policy, manifest.runner_policy());
    let registration = RegisterWorkflowRuntimePolicy::new(
        manifest.tenant().clone(),
        manifest.repository_id(),
        runtime_policy.revision,
        policy,
        applied_at,
    )
    .expect("fixture runtime-policy registration");
    let manifest = BootstrapGithubProviderManifest::new(manifest, applied_at)
        .expect("fixture manifest bootstrap");
    BootstrapGithubProviderRepository::new(registration, manifest)
        .expect("fixture repository bootstrap")
}

fn fixture_workflow_runtime_policy(revision: u64) -> WorkflowRuntimePolicy {
    if revision == 1 {
        return WorkflowRuntimePolicy::decode_configuration(FIXTURE_RUNTIME_POLICY)
            .expect("fixture runtime policy");
    }
    let configured = String::from_utf8(FIXTURE_RUNTIME_POLICY.to_vec())
        .expect("fixture runtime policy is UTF-8")
        .replace(
            "\"selector\":\"Ubuntu-24.04\"",
            &format!("\"selector\":\"Ubuntu-24.04-r{revision}\""),
        );
    WorkflowRuntimePolicy::decode_configuration(configured.as_bytes())
        .expect("rotated fixture runtime policy")
}
