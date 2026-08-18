//! Canonical historical runner, permission, resource, and workspace policy for GitHub activations.

use automata_ci_core::RunId;
use automata_ci_store::{
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, MAX_WORKFLOW_RUNTIME_POLICY_BYTES,
    MAX_WORKFLOW_RUNTIME_POLICY_FEATURES, MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS,
    MAX_WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURES, WORKFLOW_RUNTIME_POLICY_MEDIA_TYPE,
    WorkflowRuntimePolicy,
};
use automata_ci_workflow_actions::{GithubRunnerProfileCatalog, GithubRunnerProfileMapping};
use thiserror::Error;

/// Exact immutable media type for a canonical runner-policy blob.
pub const GITHUB_RUNNER_POLICY_MEDIA_TYPE: &str = WORKFLOW_RUNTIME_POLICY_MEDIA_TYPE;
/// Maximum canonical encoded runner-policy size.
pub const MAX_GITHUB_RUNNER_POLICY_BYTES: usize = MAX_WORKFLOW_RUNTIME_POLICY_BYTES;
/// Maximum exact selector mappings retained by one policy.
pub const MAX_GITHUB_RUNNER_POLICY_MAPPINGS: usize = MAX_WORKFLOW_RUNTIME_POLICY_MAPPINGS;
/// Maximum provider-neutral container features retained by one mapping.
pub const MAX_GITHUB_RUNNER_POLICY_CONTAINER_FEATURES: usize = MAX_WORKFLOW_RUNTIME_POLICY_FEATURES;
/// Maximum known runner-runtime features retained by one profile.
pub const MAX_GITHUB_RUNNER_POLICY_RUNNER_FEATURES: usize =
    MAX_WORKFLOW_RUNTIME_POLICY_RUNNER_FEATURES;

/// Validated immutable GitHub runtime-policy contract.
///
/// Store owns the sole canonical codec and semantic digest. This service type
/// is only the GitHub runner-catalog projection of that exact value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubRunnerPolicy {
    policy: WorkflowRuntimePolicy,
    catalog: GithubRunnerProfileCatalog,
}

impl GithubRunnerPolicy {
    /// Decodes trusted configuration and canonicalizes its policy value.
    ///
    /// Unlike [`Self::decode_canonical`], configuration input may use arbitrary
    /// insignificant JSON whitespace and object-key ordering.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unknown, excessive, ambiguous, or unsupported policy.
    pub fn decode_configuration(encoded: &[u8]) -> Result<Self, GithubRunnerPolicyError> {
        WorkflowRuntimePolicy::decode_configuration(encoded)
            .map_err(|_| GithubRunnerPolicyError)
            .and_then(Self::from_runtime_policy)
    }

    /// Decodes immutable blob bytes and requires their exact canonical form.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, unknown, excessive, ambiguous, or
    /// unsupported policy.
    pub fn decode_canonical(encoded: &[u8]) -> Result<Self, GithubRunnerPolicyError> {
        WorkflowRuntimePolicy::decode_canonical(encoded)
            .map_err(|_| GithubRunnerPolicyError)
            .and_then(Self::from_runtime_policy)
    }

    fn from_runtime_policy(policy: WorkflowRuntimePolicy) -> Result<Self, GithubRunnerPolicyError> {
        let mappings = policy
            .mappings()
            .iter()
            .map(|mapping| {
                GithubRunnerProfileMapping::new(
                    mapping.selector().as_str(),
                    mapping.environment().clone(),
                    mapping.operating_system().clone(),
                    mapping.architecture().clone(),
                )
                .map(|mapping_value| {
                    let mut mapping_value = mapping_value
                        .with_container_features(mapping.container_features().iter().cloned());
                    if let Some(policy) = mapping.runner_feature_policy() {
                        mapping_value = mapping_value
                            .with_supported_runner_features(policy.supported().iter().cloned());
                    }
                    mapping_value
                })
                .map_err(|_| GithubRunnerPolicyError)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let catalog =
            GithubRunnerProfileCatalog::new(mappings).map_err(|_| GithubRunnerPolicyError)?;
        Ok(Self { policy, catalog })
    }

    /// Encodes the exact content-addressed representation.
    ///
    /// # Errors
    ///
    /// Returns an error only if the validated policy cannot fit its fixed bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GithubRunnerPolicyError> {
        self.policy
            .canonical_bytes()
            .map_err(|_| GithubRunnerPolicyError)
    }

    /// Returns the sole typed relational runtime-policy value.
    #[must_use]
    pub const fn runtime_policy(&self) -> &WorkflowRuntimePolicy {
        &self.policy
    }

    /// Returns the exact selector catalog authenticated by this historical blob.
    #[must_use]
    pub const fn catalog(&self) -> &GithubRunnerProfileCatalog {
        &self.catalog
    }

    /// Derives the only current workspace path for one exact logical job.
    ///
    /// # Panics
    ///
    /// Panics only if the already-validated fixed policy can no longer derive
    /// its bounded workspace representation, which would violate the policy
    /// value's construction invariant.
    #[must_use]
    pub fn workspace(
        &self,
        run_id: RunId,
        invocation_id: LogicalWorkflowInvocationId,
        logical_job_id: LogicalWorkflowJobId,
    ) -> String {
        self.policy
            .derive_workspace(run_id, invocation_id, logical_job_id)
            .expect("validated policy uses the fixed bounded workspace derivation")
            .as_str()
            .to_owned()
    }
}

/// Sanitized invalid historical runner-policy value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub runner policy is invalid")]
pub struct GithubRunnerPolicyError;

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const POLICY: &[u8] = br#"{
      "workspace":{"derivation":1,"root":"/__w","schema":1},
      "mappings":[{
        "runner_features":{"schema":1,"supported":["automata.core/bash-shell@v1","automata.core/command-files@v1","automata.core/default-posix-shell@v1","automata.core/job-summaries@v1","automata.core/sh-shell@v1","automata.core/shell-steps@v1"]},
        "container_features":["automata.core/job-containers@v1"],
        "architecture":"x86_64",
        "operating_system":"linux",
        "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
        "selector":"Ubuntu-24.04"
      }],
      "permissions":{
        "provider_default":{"contents":"read","packages":"read"},
        "read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},
        "write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}
      },
      "resources":{
        "defaults":{
          "requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},
          "limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}
        },
        "minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},
        "maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}
      },
      "schema":2
    }"#;

    #[test]
    fn configuration_canonicalizes_and_blob_decode_rejects_alias_bytes() {
        let policy = GithubRunnerPolicy::decode_configuration(POLICY).expect("configuration");
        let canonical = policy.canonical_bytes().expect("canonical policy");
        assert_ne!(canonical, POLICY);
        assert_eq!(
            GithubRunnerPolicy::decode_canonical(&canonical).expect("historical blob"),
            policy
        );
        assert!(GithubRunnerPolicy::decode_canonical(POLICY).is_err());
        let selector = automata_ci_core::RunnerLabel::new("ubuntu-24.04").expect("selector");
        assert!(
            policy
                .catalog()
                .get(&selector)
                .expect("profile")
                .supported_runner_features()
                .expect("feature policy")
                .contains(&automata_ci_core::RunnerFeature::BASH_SHELL)
        );
    }

    #[test]
    fn workspace_is_pure_and_identity_complete() {
        let policy = GithubRunnerPolicy::decode_configuration(POLICY).expect("configuration");
        let run = RunId::new();
        let invocation =
            LogicalWorkflowInvocationId::from_uuid(Uuid::new_v4()).expect("logical invocation");
        let job = LogicalWorkflowJobId::from_uuid(Uuid::new_v4()).expect("logical job");
        assert_eq!(
            policy.workspace(run, invocation, job),
            format!(
                "/__w/{}/{}/{}",
                run.as_uuid(),
                invocation.as_uuid(),
                job.as_uuid()
            )
        );
    }
}
