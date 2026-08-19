//! Immutable, revisioned GitHub provider configuration for product bootstrap.
//!
//! Static configuration is the desired source, while this repository retains
//! the exact non-secret revision that provider activity pins. Historical
//! revisions remain readable after the current pointer advances. Webhook
//! secrets, App private keys, and credential values never enter this boundary.

use std::num::NonZeroU64;

use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use automata_ci_core::JobAuthorityProfile;

use crate::{
    AdmissionObject, GithubCheckAppId, GithubCheckName, GithubCheckSubjectKey,
    GithubInstallationId, GithubRepositoryId, GithubRepositoryName, GithubRepositoryOwnerId,
    GithubRepositoryVisibility, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, RegisterWorkflowRuntimePolicy,
    RepositoryId, RepositoryOperationError, Sha256Digest, TenantScope,
    WorkflowRuntimePolicyReceipt, WorkflowRuntimePolicyRevision,
};
use automata_ci_provider::ProviderConnectionId;

/// Exact media type of one canonical historical runner policy.
pub const GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE: &str =
    "application/vnd.automata.github-runner-policy+json";
/// Maximum encoded size of one historical runner policy.
pub const GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES: u64 = 64 * 1_024;

/// Exact current GitHub.com browser origin pinned by the provider manifest.
pub const GITHUB_PROVIDER_WEB_ORIGIN: &str = "https://github.com/";
/// Exact current GitHub.com API origin pinned by the provider manifest.
pub const GITHUB_PROVIDER_API_ORIGIN: &str = "https://api.github.com/";
/// Exact credential-free GitHub.com archive origin pinned by the manifest.
pub const GITHUB_PROVIDER_ARCHIVE_ORIGIN: &str = "https://codeload.github.com/";
/// Exact GitHub REST API version sent by every provider HTTP client.
pub const GITHUB_PROVIDER_REST_API_VERSION: &str = "2026-03-10";
/// Exact media type accepted from GitHub REST JSON endpoints.
pub const GITHUB_PROVIDER_REST_ACCEPT: &str = "application/vnd.github+json";
/// Exact media type accepted from the credential-free archive endpoint.
pub const GITHUB_PROVIDER_ARCHIVE_ACCEPT: &str = "application/octet-stream";
/// Public repositories use no credential for exact-SHA source reads.
pub const GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION: &str = "direct_public_archive";
/// Private repositories require a repository-scoped GitHub App installation token.
pub const GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION: &str = "github_app_installation_token";
/// Repository source is always resolved and rechecked as an exact commit SHA.
pub const GITHUB_PROVIDER_SOURCE_REVISION: &str = "exact_sha";
/// Repository discovery consumes a gzip-compressed tar archive.
pub const GITHUB_PROVIDER_ARCHIVE_FORMAT: &str = "tar_gzip";
/// Durable aggregate selector used by repository-wide direct-workflow discovery.
///
/// This is a server-owned policy key, not a workflow filename. Concrete job
/// Checks retain their evaluated display names; workflows have no Check name.
pub const GITHUB_PROVIDER_ALL_DIRECT_WORKFLOWS_KEY: &str = ".ci/workflows";
/// The only provider event admitted by the initial dogfood manifest.
pub const GITHUB_PROVIDER_EVENT: &str = "push";
/// Default branch ref used by manifest constructors.
pub const GITHUB_PROVIDER_GIT_REF: &str = "refs/heads/main";
/// GitHub's documented maximum webhook payload size.
pub const GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES: u64 = 25 * 1_024 * 1_024;
/// Application deadline below the dedicated edge's response-header deadline.
pub const GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS: u64 = 7_000;
/// Maximum commit summaries retained from one authenticated push payload.
pub const GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS: u64 = 2_048;
/// Maximum push commits for which webhook metadata is complete for path filters.
pub const GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS: u64 = 1_000;
/// Maximum provider changed-file records selected for pull-request path filters.
///
/// This matches the documented 3,000-record GitHub Actions and Pull-request
/// Files REST window and is retained exactly in durable manifest replay.
pub const GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES: u64 = 3_000;
/// Exact compressed repository-archive ceiling supported by discovery.
pub const GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES: u64 = 256 * 1_024 * 1_024;
/// Exact gzip-decoded repository-archive ceiling supported by discovery.
pub const GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES: u64 = 2 * 1_024 * 1_024 * 1_024;
/// Exact repository-archive entry-count ceiling supported by discovery.
pub const GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES: u64 = 100_000;
/// Exact sum-of-entry-sizes ceiling supported by discovery.
pub const GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES: u64 = 1_024 * 1_024 * 1_024;
/// Exact encoded archive-entry path ceiling supported by discovery.
pub const GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES: u64 = 4 * 1_024;
/// Exact direct workflow-file count ceiling supported by discovery.
pub const GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS: u64 = 256;
/// Exact raw UTF-8 per-workflow source ceiling supported by discovery.
///
/// This duplicates the provider frontend's 500 KiB boundary deliberately so
/// the persistence layer does not acquire a dependency on the frontend.
pub const GITHUB_PROVIDER_WORKFLOW_MAX_BYTES: u64 = 500 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubProviderManifestLimitRejection {
    RunnerPolicyBytes,
    ArchiveCompressedBytes,
    ArchiveDecompressedBytes,
    ArchiveEntries,
    ArchiveExpandedBytes,
    ArchiveEntryPathBytes,
    ArchiveWorkflows,
    WorkflowBytes,
}

const fn runner_policy_bytes_rejection(
    observed: u64,
) -> Option<GithubProviderManifestLimitRejection> {
    if observed > GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES {
        return Some(GithubProviderManifestLimitRejection::RunnerPolicyBytes);
    }
    None
}

const fn archive_compressed_bytes_rejection(
    observed: u64,
) -> Option<GithubProviderManifestLimitRejection> {
    if observed > GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES {
        return Some(GithubProviderManifestLimitRejection::ArchiveCompressedBytes);
    }
    None
}

const fn archive_decompressed_bytes_rejection(
    observed: u64,
) -> Option<GithubProviderManifestLimitRejection> {
    if observed > GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES {
        return Some(GithubProviderManifestLimitRejection::ArchiveDecompressedBytes);
    }
    None
}

const fn archive_entries_rejection(observed: u64) -> Option<GithubProviderManifestLimitRejection> {
    if observed > GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES {
        return Some(GithubProviderManifestLimitRejection::ArchiveEntries);
    }
    None
}

const fn archive_expanded_bytes_rejection(
    observed: u64,
) -> Option<GithubProviderManifestLimitRejection> {
    if observed > GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES {
        return Some(GithubProviderManifestLimitRejection::ArchiveExpandedBytes);
    }
    None
}

const fn archive_entry_path_bytes_rejection(
    observed: u64,
) -> Option<GithubProviderManifestLimitRejection> {
    if observed > GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES {
        return Some(GithubProviderManifestLimitRejection::ArchiveEntryPathBytes);
    }
    None
}

const fn archive_workflows_rejection(
    observed: u64,
) -> Option<GithubProviderManifestLimitRejection> {
    if observed > GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS {
        return Some(GithubProviderManifestLimitRejection::ArchiveWorkflows);
    }
    None
}

const fn workflow_bytes_rejection(observed: u64) -> Option<GithubProviderManifestLimitRejection> {
    if observed > GITHUB_PROVIDER_WORKFLOW_MAX_BYTES {
        return Some(GithubProviderManifestLimitRejection::WorkflowBytes);
    }
    None
}

const MANIFEST_DIGEST_DOMAIN: &[u8] = b"automata.store.github-provider-manifest\0";
const REPOSITORY_ID_DOMAIN: &[u8] = b"automata.admission.repository.v1\0";

/// Domain required when secret custody derives the public webhook verifier fingerprint.
///
/// The trusted secret loader computes SHA-256 over this domain followed by at
/// least 32 uniformly random verifier-key bytes. Only that 32-byte fingerprint,
/// never the verifier key, enters the provider-manifest boundary.
pub const GITHUB_PROVIDER_WEBHOOK_VERIFIER_FINGERPRINT_DOMAIN: &[u8] =
    b"automata.store.github-webhook-verifier-fingerprint.v1\0";

/// Positive immutable provider-manifest revision within the signed 64-bit storage boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubProviderManifestRevision(NonZeroU64);

impl GithubProviderManifestRevision {
    /// Constructs a positive manifest revision.
    ///
    /// # Errors
    ///
    /// Rejects zero and values outside the signed 64-bit storage boundary.
    pub fn new(value: u64) -> Result<Self, GithubProviderManifestValueError> {
        let value = NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(GithubProviderManifestValueError::InvalidRevision)?;
        Ok(Self(value))
    }

    /// Returns the positive revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Positive generation of a repository's GitHub App installation binding.
///
/// The generation advances only when the installation identifier is replaced;
/// ordinary policy, key, and verifier revisions retain the current generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubInstallationBindingGeneration(NonZeroU64);

impl GithubInstallationBindingGeneration {
    /// Constructs a positive generation inside the signed durable range.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, GithubProviderManifestValueError> {
        NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .map(Self)
            .ok_or(GithubProviderManifestValueError::InvalidInstallationBindingGeneration)
    }

    /// Returns the initial binding generation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Returns the positive generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Canonical full default-branch reference pinned by a provider manifest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubProviderGitRef(String);

impl GithubProviderGitRef {
    /// Validates a full `refs/heads/...` reference.
    ///
    /// # Errors
    ///
    /// Rejects non-branch refs and branch names that violate Git's canonical
    /// component, character, or length rules.
    pub fn new(value: impl Into<String>) -> Result<Self, GithubProviderManifestValueError> {
        let value = value.into();
        let Some(branch) = value.strip_prefix("refs/heads/") else {
            return Err(GithubProviderManifestValueError::InvalidGitRef);
        };
        if value.len() > 1_024 || !canonical_branch_name(branch) {
            return Err(GithubProviderManifestValueError::InvalidGitRef);
        }
        Ok(Self(value))
    }

    /// Returns the canonical default branch reference.
    ///
    /// # Panics
    ///
    /// Panics only if the compile-time main reference stops satisfying the
    /// canonical branch-ref invariant.
    #[must_use]
    pub fn main() -> Self {
        Self::new(GITHUB_PROVIDER_GIT_REF).expect("fixed main ref is canonical")
    }

    /// Returns the exact full branch reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Non-secret fingerprint of one high-entropy webhook verifier key revision.
///
/// This type accepts only a precomputed, domain-separated SHA-256 fingerprint;
/// it has no constructor from verifier-key bytes. The secret-custody boundary
/// must derive it using [`GITHUB_PROVIDER_WEBHOOK_VERIFIER_FINGERPRINT_DOMAIN`]
/// and at least 256 bits of uniformly random key material.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GithubProviderWebhookVerifierFingerprint(Sha256Digest);

impl GithubProviderWebhookVerifierFingerprint {
    /// Constructs non-secret verifier-material evidence.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero sentinel. Raw verifier keys must never be
    /// passed into or hashed by this Store API.
    pub fn from_sha256(
        fingerprint: Sha256Digest,
    ) -> Result<Self, GithubProviderManifestValueError> {
        if fingerprint.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(GithubProviderManifestValueError::InvalidWebhookVerifierFingerprint);
        }
        Ok(Self(fingerprint))
    }

    /// Returns the public domain-separated SHA-256 fingerprint.
    #[must_use]
    pub const fn sha256(self) -> Sha256Digest {
        self.0
    }
}

/// Exact fixed GitHub.com origins retained as manifest evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubProviderOrigins;

impl GithubProviderOrigins {
    /// Selects the only currently supported trusted origin pair.
    #[must_use]
    pub const fn github_dot_com() -> Self {
        Self
    }

    /// Returns the browser/server origin exposed to GitHub-compatible jobs.
    #[must_use]
    pub const fn web_origin(self) -> &'static str {
        GITHUB_PROVIDER_WEB_ORIGIN
    }

    /// Returns the fixed provider API root.
    #[must_use]
    pub const fn api_origin(self) -> &'static str {
        GITHUB_PROVIDER_API_ORIGIN
    }

    /// Returns the credential-free archive download origin.
    #[must_use]
    pub const fn archive_origin(self) -> &'static str {
        GITHUB_PROVIDER_ARCHIVE_ORIGIN
    }
}

/// Validated immutable descriptor of one canonical historical runner policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProviderRunnerPolicyObject(AdmissionObject);

impl GithubProviderRunnerPolicyObject {
    /// Validates a runner-policy object descriptor before manifest binding.
    ///
    /// # Errors
    ///
    /// Rejects the wrong media type or an object outside the exact 64-KiB bound.
    pub fn new(object: AdmissionObject) -> Result<Self, GithubProviderManifestValueError> {
        let expected_key = format!("github/runner-policy/v1/{}.json", object.digest());
        if object.media_type() != GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE
            || object.encoded_size() == 0
            || runner_policy_bytes_rejection(object.encoded_size()).is_some()
            || object.object_key().as_str() != expected_key
        {
            return Err(GithubProviderManifestValueError::InvalidRunnerPolicyObject);
        }
        Ok(Self(object))
    }

    /// Returns the credential-free immutable object descriptor.
    #[must_use]
    pub const fn object(&self) -> &AdmissionObject {
        &self.0
    }
}

/// Bounded webhook and repository-discovery limits pinned by one revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubProviderManifestLimits {
    webhook_max_body_bytes: u64,
    webhook_accept_timeout_millis: u64,
    push_webhook_max_commits: u64,
    path_filter_max_commits: u64,
    path_filter_max_changed_files: u64,
    archive_max_compressed_bytes: u64,
    archive_max_decompressed_bytes: u64,
    archive_max_entries: u64,
    archive_max_expanded_bytes: u64,
    archive_max_entry_path_bytes: u64,
    archive_max_workflows: u64,
    workflow_max_bytes: u64,
}

/// Immutable direct-workflow discovery policy pinned by one provider manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProviderWorkflowSelection;

impl GithubProviderWorkflowSelection {
    /// Constructs the repository-wide direct-workflow policy.
    #[must_use]
    pub const fn all_direct() -> Self {
        Self
    }

    /// Returns the stable durable policy kind.
    #[must_use]
    pub const fn as_durable_str(&self) -> &'static str {
        "all_direct"
    }

    /// Reports whether one canonical discovered path is selected.
    #[must_use]
    pub fn selects(&self, path: &str) -> bool {
        canonical_direct_workflow_path(path)
    }
}

impl GithubProviderManifestLimits {
    /// Constructs one coherent provider resource policy.
    ///
    /// Every value is deliberately exact. A different webhook value disagrees
    /// with the dedicated edge, while different discovery values are not the
    /// policy supported by the current repository frontend. A future supported
    /// policy requires a new closed manifest contract rather than an unproven
    /// number that merely fits a broad range.
    ///
    /// # Errors
    ///
    /// Rejects an incoherent, zero, or excessive limit set.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        webhook_max_body_bytes: u64,
        webhook_accept_timeout_millis: u64,
        push_webhook_max_commits: u64,
        path_filter_max_commits: u64,
        path_filter_max_changed_files: u64,
        archive_max_compressed_bytes: u64,
        archive_max_decompressed_bytes: u64,
        archive_max_entries: u64,
        archive_max_expanded_bytes: u64,
        archive_max_entry_path_bytes: u64,
        archive_max_workflows: u64,
        workflow_max_bytes: u64,
    ) -> Result<Self, GithubProviderManifestValueError> {
        if webhook_max_body_bytes != GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES
            || webhook_accept_timeout_millis != GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS
            || push_webhook_max_commits != GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS
            || path_filter_max_commits != GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS
            || path_filter_max_changed_files != GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES
            || archive_compressed_bytes_rejection(archive_max_compressed_bytes).is_some()
            || archive_decompressed_bytes_rejection(archive_max_decompressed_bytes).is_some()
            || archive_entries_rejection(archive_max_entries).is_some()
            || archive_expanded_bytes_rejection(archive_max_expanded_bytes).is_some()
            || archive_entry_path_bytes_rejection(archive_max_entry_path_bytes).is_some()
            || archive_workflows_rejection(archive_max_workflows).is_some()
            || workflow_bytes_rejection(workflow_max_bytes).is_some()
            || archive_max_compressed_bytes != GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES
            || archive_max_decompressed_bytes != GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES
            || archive_max_entries != GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES
            || archive_max_expanded_bytes != GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES
            || archive_max_entry_path_bytes != GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES
            || archive_max_workflows != GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS
            || workflow_max_bytes != GITHUB_PROVIDER_WORKFLOW_MAX_BYTES
        {
            return Err(GithubProviderManifestValueError::InvalidLimits);
        }
        Ok(Self {
            webhook_max_body_bytes,
            webhook_accept_timeout_millis,
            push_webhook_max_commits,
            path_filter_max_commits,
            path_filter_max_changed_files,
            archive_max_compressed_bytes,
            archive_max_decompressed_bytes,
            archive_max_entries,
            archive_max_expanded_bytes,
            archive_max_entry_path_bytes,
            archive_max_workflows,
            workflow_max_bytes,
        })
    }

    /// Returns the production GitHub.com dogfood limits.
    #[must_use]
    pub const fn github_dot_com_ci() -> Self {
        Self {
            webhook_max_body_bytes: GITHUB_PROVIDER_WEBHOOK_MAX_BODY_BYTES,
            webhook_accept_timeout_millis: GITHUB_PROVIDER_WEBHOOK_ACCEPT_TIMEOUT_MILLIS,
            push_webhook_max_commits: GITHUB_PROVIDER_PUSH_WEBHOOK_MAX_COMMITS,
            path_filter_max_commits: GITHUB_PROVIDER_PATH_FILTER_MAX_COMMITS,
            path_filter_max_changed_files: GITHUB_PROVIDER_PATH_FILTER_MAX_CHANGED_FILES,
            archive_max_compressed_bytes: GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES,
            archive_max_decompressed_bytes: GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES,
            archive_max_entries: GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES,
            archive_max_expanded_bytes: GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES,
            archive_max_entry_path_bytes: GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES,
            archive_max_workflows: GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS,
            workflow_max_bytes: GITHUB_PROVIDER_WORKFLOW_MAX_BYTES,
        }
    }

    /// Returns the exact webhook body ceiling.
    #[must_use]
    pub const fn webhook_max_body_bytes(self) -> u64 {
        self.webhook_max_body_bytes
    }
    /// Returns the application acceptance deadline in milliseconds.
    #[must_use]
    pub const fn webhook_accept_timeout_millis(self) -> u64 {
        self.webhook_accept_timeout_millis
    }
    /// Returns the authenticated push-payload commit-summary ceiling.
    #[must_use]
    pub const fn push_webhook_max_commits(self) -> u64 {
        self.push_webhook_max_commits
    }
    /// Returns the path-filter complete-push commit ceiling.
    #[must_use]
    pub const fn path_filter_max_commits(self) -> u64 {
        self.path_filter_max_commits
    }
    /// Returns the upstream REST changed-file transport ceiling.
    #[must_use]
    pub const fn path_filter_max_changed_files(self) -> u64 {
        self.path_filter_max_changed_files
    }
    /// Returns the compressed repository archive ceiling.
    #[must_use]
    pub const fn archive_max_compressed_bytes(self) -> u64 {
        self.archive_max_compressed_bytes
    }
    /// Returns the decompressed stream ceiling.
    #[must_use]
    pub const fn archive_max_decompressed_bytes(self) -> u64 {
        self.archive_max_decompressed_bytes
    }
    /// Returns the maximum archive entry count.
    #[must_use]
    pub const fn archive_max_entries(self) -> u64 {
        self.archive_max_entries
    }
    /// Returns the sum-of-entry-sizes ceiling.
    #[must_use]
    pub const fn archive_max_expanded_bytes(self) -> u64 {
        self.archive_max_expanded_bytes
    }
    /// Returns the maximum encoded archive path length.
    #[must_use]
    pub const fn archive_max_entry_path_bytes(self) -> u64 {
        self.archive_max_entry_path_bytes
    }
    /// Returns the maximum discovered workflow count.
    #[must_use]
    pub const fn archive_max_workflows(self) -> u64 {
        self.archive_max_workflows
    }
    /// Returns the maximum bytes retained for one workflow.
    #[must_use]
    pub const fn workflow_max_bytes(self) -> u64 {
        self.workflow_max_bytes
    }
}

/// Complete immutable non-secret configuration of one GitHub provider revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProviderManifest {
    tenant: TenantScope,
    repository_id: RepositoryId,
    connection_id: ProviderConnectionId,
    installation_id: GithubInstallationId,
    installation_binding_generation: GithubInstallationBindingGeneration,
    github_repository_id: GithubRepositoryId,
    github_repository_owner_id: Option<GithubRepositoryOwnerId>,
    github_repository_name: GithubRepositoryName,
    repository_visibility: GithubRepositoryVisibility,
    github_app_id: GithubServerServiceAppId,
    app_client_id: GithubServerServiceAppClientId,
    jwt_issuer: GithubServerServiceJwtIssuer,
    app_key_spki_sha256: Sha256Digest,
    app_configuration_revision: GithubServerServiceRevision,
    webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
    webhook_verifier_revision: GithubServerServiceRevision,
    policy_revision: GithubServerServiceRevision,
    authority_profile: JobAuthorityProfile,
    runner_policy: GithubProviderRunnerPolicyObject,
    runtime_policy_revision: WorkflowRuntimePolicyRevision,
    runtime_policy_digest: Sha256Digest,
    workflow_selection: GithubProviderWorkflowSelection,
    git_ref: GithubProviderGitRef,
    check_subject_key: GithubCheckSubjectKey,
    check_name: GithubCheckName,
    origins: GithubProviderOrigins,
    limits: GithubProviderManifestLimits,
    revision: GithubProviderManifestRevision,
    digest: Sha256Digest,
}

impl GithubProviderManifest {
    /// Constructs one exact `automata-ci/automata`-style provider policy.
    ///
    /// The internal repository ID and Check subject key are server-derived.
    /// Visibility, event, ref, and origins are closed current policy. The
    /// every canonical direct workflow is selected.
    ///
    /// # Panics
    ///
    /// Panics only if the compile-time workflow path stops satisfying the
    /// canonical Check-subject-key invariant.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        tenant: TenantScope,
        connection_id: ProviderConnectionId,
        installation_id: GithubInstallationId,
        github_repository_id: GithubRepositoryId,
        github_repository_name: GithubRepositoryName,
        repository_visibility: GithubRepositoryVisibility,
        github_app_id: GithubServerServiceAppId,
        app_client_id: GithubServerServiceAppClientId,
        jwt_issuer: GithubServerServiceJwtIssuer,
        app_key_spki_sha256: Sha256Digest,
        app_configuration_revision: GithubServerServiceRevision,
        webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        webhook_verifier_revision: GithubServerServiceRevision,
        policy_revision: GithubServerServiceRevision,
        authority_profile: JobAuthorityProfile,
        runner_policy: GithubProviderRunnerPolicyObject,
        runtime_policy_revision: WorkflowRuntimePolicyRevision,
        runtime_policy_digest: Sha256Digest,
        check_name: GithubCheckName,
        origins: GithubProviderOrigins,
        limits: GithubProviderManifestLimits,
        revision: GithubProviderManifestRevision,
    ) -> Self {
        Self::new_with_workflow_selection(
            tenant,
            connection_id,
            installation_id,
            github_repository_id,
            github_repository_name,
            repository_visibility,
            github_app_id,
            app_client_id,
            jwt_issuer,
            app_key_spki_sha256,
            app_configuration_revision,
            webhook_verifier_fingerprint,
            webhook_verifier_revision,
            policy_revision,
            authority_profile,
            runner_policy,
            runtime_policy_revision,
            runtime_policy_digest,
            GithubProviderWorkflowSelection::all_direct(),
            check_name,
            origins,
            limits,
            revision,
        )
    }

    /// Constructs one exact provider policy with an explicit discovery mode.
    ///
    /// # Panics
    ///
    /// Panics only if the compile-time all-direct aggregate key stops satisfying
    /// the shared Check-subject invariant.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new_with_workflow_selection(
        tenant: TenantScope,
        connection_id: ProviderConnectionId,
        installation_id: GithubInstallationId,
        github_repository_id: GithubRepositoryId,
        github_repository_name: GithubRepositoryName,
        repository_visibility: GithubRepositoryVisibility,
        github_app_id: GithubServerServiceAppId,
        app_client_id: GithubServerServiceAppClientId,
        jwt_issuer: GithubServerServiceJwtIssuer,
        app_key_spki_sha256: Sha256Digest,
        app_configuration_revision: GithubServerServiceRevision,
        webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        webhook_verifier_revision: GithubServerServiceRevision,
        policy_revision: GithubServerServiceRevision,
        authority_profile: JobAuthorityProfile,
        runner_policy: GithubProviderRunnerPolicyObject,
        runtime_policy_revision: WorkflowRuntimePolicyRevision,
        runtime_policy_digest: Sha256Digest,
        workflow_selection: GithubProviderWorkflowSelection,
        check_name: GithubCheckName,
        origins: GithubProviderOrigins,
        limits: GithubProviderManifestLimits,
        revision: GithubProviderManifestRevision,
    ) -> Self {
        Self::new_with_workflow_selection_and_git_ref(
            tenant,
            connection_id,
            installation_id,
            github_repository_id,
            github_repository_name,
            repository_visibility,
            github_app_id,
            app_client_id,
            jwt_issuer,
            app_key_spki_sha256,
            app_configuration_revision,
            webhook_verifier_fingerprint,
            webhook_verifier_revision,
            policy_revision,
            authority_profile,
            runner_policy,
            runtime_policy_revision,
            runtime_policy_digest,
            workflow_selection,
            GithubProviderGitRef::main(),
            check_name,
            origins,
            limits,
            revision,
        )
    }

    /// Constructs one provider policy with explicit workflow and branch selection.
    ///
    /// # Panics
    ///
    /// Panics only if the compile-time all-direct aggregate key stops satisfying
    /// the shared Check-subject invariant.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new_with_workflow_selection_and_git_ref(
        tenant: TenantScope,
        connection_id: ProviderConnectionId,
        installation_id: GithubInstallationId,
        github_repository_id: GithubRepositoryId,
        github_repository_name: GithubRepositoryName,
        repository_visibility: GithubRepositoryVisibility,
        github_app_id: GithubServerServiceAppId,
        app_client_id: GithubServerServiceAppClientId,
        jwt_issuer: GithubServerServiceJwtIssuer,
        app_key_spki_sha256: Sha256Digest,
        app_configuration_revision: GithubServerServiceRevision,
        webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        webhook_verifier_revision: GithubServerServiceRevision,
        policy_revision: GithubServerServiceRevision,
        authority_profile: JobAuthorityProfile,
        runner_policy: GithubProviderRunnerPolicyObject,
        runtime_policy_revision: WorkflowRuntimePolicyRevision,
        runtime_policy_digest: Sha256Digest,
        workflow_selection: GithubProviderWorkflowSelection,
        git_ref: GithubProviderGitRef,
        check_name: GithubCheckName,
        origins: GithubProviderOrigins,
        limits: GithubProviderManifestLimits,
        revision: GithubProviderManifestRevision,
    ) -> Self {
        let repository_id = github_provider_repository_id(&tenant, github_repository_id);
        let check_subject_key =
            GithubCheckSubjectKey::new(GITHUB_PROVIDER_ALL_DIRECT_WORKFLOWS_KEY)
                .expect("fixed all-direct selector is a canonical Check subject key");
        let mut manifest = Self {
            tenant,
            repository_id,
            connection_id,
            installation_id,
            installation_binding_generation: GithubInstallationBindingGeneration::initial(),
            github_repository_id,
            github_repository_owner_id: None,
            github_repository_name,
            repository_visibility,
            github_app_id,
            app_client_id,
            jwt_issuer,
            app_key_spki_sha256,
            app_configuration_revision,
            webhook_verifier_fingerprint,
            webhook_verifier_revision,
            policy_revision,
            authority_profile,
            runner_policy,
            runtime_policy_revision,
            runtime_policy_digest,
            workflow_selection,
            git_ref,
            check_subject_key,
            check_name,
            origins,
            limits,
            revision,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        manifest.digest = manifest.compute_digest();
        manifest
    }

    /// Constructs a provider policy whose numeric repository owner is immutable evidence.
    ///
    /// Schedule discovery requires numeric repository-owner evidence.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new_owner_bound_with_workflow_selection_and_git_ref(
        tenant: TenantScope,
        connection_id: ProviderConnectionId,
        installation_id: GithubInstallationId,
        github_repository_id: GithubRepositoryId,
        github_repository_owner_id: GithubRepositoryOwnerId,
        github_repository_name: GithubRepositoryName,
        repository_visibility: GithubRepositoryVisibility,
        github_app_id: GithubServerServiceAppId,
        app_client_id: GithubServerServiceAppClientId,
        jwt_issuer: GithubServerServiceJwtIssuer,
        app_key_spki_sha256: Sha256Digest,
        app_configuration_revision: GithubServerServiceRevision,
        webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        webhook_verifier_revision: GithubServerServiceRevision,
        policy_revision: GithubServerServiceRevision,
        authority_profile: JobAuthorityProfile,
        runner_policy: GithubProviderRunnerPolicyObject,
        runtime_policy_revision: WorkflowRuntimePolicyRevision,
        runtime_policy_digest: Sha256Digest,
        workflow_selection: GithubProviderWorkflowSelection,
        git_ref: GithubProviderGitRef,
        check_name: GithubCheckName,
        origins: GithubProviderOrigins,
        limits: GithubProviderManifestLimits,
        revision: GithubProviderManifestRevision,
    ) -> Self {
        let manifest = Self::new_with_workflow_selection_and_git_ref(
            tenant,
            connection_id,
            installation_id,
            github_repository_id,
            github_repository_name,
            repository_visibility,
            github_app_id,
            app_client_id,
            jwt_issuer,
            app_key_spki_sha256,
            app_configuration_revision,
            webhook_verifier_fingerprint,
            webhook_verifier_revision,
            policy_revision,
            authority_profile,
            runner_policy,
            runtime_policy_revision,
            runtime_policy_digest,
            workflow_selection,
            git_ref,
            check_name,
            origins,
            limits,
            revision,
        );
        manifest.with_repository_owner_id(github_repository_owner_id)
    }

    /// Binds a numeric repository owner into a new immutable digest domain.
    #[must_use]
    pub fn with_repository_owner_id(
        mut self,
        github_repository_owner_id: GithubRepositoryOwnerId,
    ) -> Self {
        self.github_repository_owner_id = Some(github_repository_owner_id);
        self.digest = self.compute_digest();
        self
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the server-derived internal repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    /// Returns the stable provider connection UUID.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }
    /// Returns the exact GitHub App installation ID.
    #[must_use]
    pub const fn installation_id(&self) -> GithubInstallationId {
        self.installation_id
    }
    /// Returns the immutable installation-binding generation.
    #[must_use]
    pub const fn installation_binding_generation(&self) -> GithubInstallationBindingGeneration {
        self.installation_binding_generation
    }
    /// Selects an explicit installation-binding generation and rebinds the digest.
    #[must_use]
    pub fn with_installation_binding_generation(
        mut self,
        generation: GithubInstallationBindingGeneration,
    ) -> Self {
        self.installation_binding_generation = generation;
        self.digest = self.compute_digest();
        self
    }
    /// Returns the stable numeric GitHub repository ID.
    #[must_use]
    pub const fn github_repository_id(&self) -> GithubRepositoryId {
        self.github_repository_id
    }
    /// Returns the immutable numeric repository owner when this revision is owner-bound.
    #[must_use]
    pub const fn github_repository_owner_id(&self) -> Option<GithubRepositoryOwnerId> {
        self.github_repository_owner_id
    }
    /// Returns the canonical case-sensitive `owner/repository` identity.
    #[must_use]
    pub const fn github_repository_name(&self) -> &GithubRepositoryName {
        &self.github_repository_name
    }
    /// Returns the fixed expected authenticated visibility.
    #[must_use]
    pub const fn repository_visibility(&self) -> GithubRepositoryVisibility {
        self.repository_visibility
    }
    /// Returns the numeric GitHub App identity.
    #[must_use]
    pub const fn github_app_id(&self) -> GithubServerServiceAppId {
        self.github_app_id
    }
    /// Returns the same App identity in the Check-subject type domain.
    ///
    /// # Panics
    ///
    /// Panics only if the shared positive App-ID domains become inconsistent.
    #[must_use]
    pub fn check_app_id(&self) -> GithubCheckAppId {
        GithubCheckAppId::new(self.github_app_id.get())
            .expect("server-service App ID fits the Check App ID domain")
    }
    /// Returns the App client identity used for JWT configuration.
    #[must_use]
    pub const fn app_client_id(&self) -> &GithubServerServiceAppClientId {
        &self.app_client_id
    }
    /// Returns the closed configured JWT issuer family.
    #[must_use]
    pub const fn jwt_issuer(&self) -> GithubServerServiceJwtIssuer {
        self.jwt_issuer
    }
    /// Returns the configured App public-key fingerprint.
    #[must_use]
    pub const fn app_key_spki_sha256(&self) -> Sha256Digest {
        self.app_key_spki_sha256
    }
    /// Returns the App configuration revision.
    #[must_use]
    pub const fn app_configuration_revision(&self) -> GithubServerServiceRevision {
        self.app_configuration_revision
    }
    /// Returns the non-secret verifier-key fingerprint pinned by this revision.
    #[must_use]
    pub const fn webhook_verifier_fingerprint(&self) -> GithubProviderWebhookVerifierFingerprint {
        self.webhook_verifier_fingerprint
    }
    /// Returns the monotonic verifier-material revision.
    #[must_use]
    pub const fn webhook_verifier_revision(&self) -> GithubServerServiceRevision {
        self.webhook_verifier_revision
    }
    /// Returns the workflow/Check policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> GithubServerServiceRevision {
        self.policy_revision
    }
    /// Returns the immutable job-visible authority profile selected for this repository.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }
    /// Returns the immutable historical runner and workspace policy descriptor.
    #[must_use]
    pub const fn runner_policy(&self) -> &GithubProviderRunnerPolicyObject {
        &self.runner_policy
    }
    /// Returns the independent sequential repository runtime-policy revision.
    #[must_use]
    pub const fn runtime_policy_revision(&self) -> WorkflowRuntimePolicyRevision {
        self.runtime_policy_revision
    }
    /// Returns the domain-separated semantic digest of the repository policy.
    #[must_use]
    pub const fn runtime_policy_digest(&self) -> Sha256Digest {
        self.runtime_policy_digest
    }
    /// Returns the immutable workflow discovery policy.
    #[must_use]
    pub const fn workflow_selection(&self) -> &GithubProviderWorkflowSelection {
        &self.workflow_selection
    }
    /// Reports whether a canonical discovered path is selected by this revision.
    #[must_use]
    pub fn selects_workflow_path(&self, path: &str) -> bool {
        self.workflow_selection.selects(path)
    }
    /// Returns the durable selection/aggregate Check key.
    ///
    /// In exact mode this is the configured workflow path. In all-direct mode
    /// it is the server-owned aggregate key, not an admitted workflow path.
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        self.check_subject_key.as_str()
    }
    /// Returns the only selected provider event.
    #[must_use]
    pub const fn event_name(&self) -> &'static str {
        GITHUB_PROVIDER_EVENT
    }
    /// Returns the manifest-pinned full default-branch ref.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        self.git_ref.as_str()
    }
    /// Returns the delivery-local Check subject key.
    #[must_use]
    pub const fn check_subject_key(&self) -> &GithubCheckSubjectKey {
        &self.check_subject_key
    }
    /// Returns the unique provider-facing Check Run name.
    #[must_use]
    pub const fn check_name(&self) -> &GithubCheckName {
        &self.check_name
    }
    /// Returns the exact trusted provider origins.
    #[must_use]
    pub const fn origins(&self) -> GithubProviderOrigins {
        self.origins
    }
    /// Returns the exact GitHub REST API version header value.
    #[must_use]
    pub const fn rest_api_version(&self) -> &'static str {
        GITHUB_PROVIDER_REST_API_VERSION
    }
    /// Returns the exact REST JSON media type.
    #[must_use]
    pub const fn rest_accept(&self) -> &'static str {
        GITHUB_PROVIDER_REST_ACCEPT
    }
    /// Returns the exact archive response media type.
    #[must_use]
    pub const fn archive_accept(&self) -> &'static str {
        GITHUB_PROVIDER_ARCHIVE_ACCEPT
    }
    /// Returns the credential behavior coupled to this revision's visibility.
    #[must_use]
    pub const fn source_authentication(&self) -> &'static str {
        match self.repository_visibility {
            GithubRepositoryVisibility::Public => GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION,
            GithubRepositoryVisibility::Private => GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION,
        }
    }
    /// Returns the exact revision-selection behavior.
    #[must_use]
    pub const fn source_revision(&self) -> &'static str {
        GITHUB_PROVIDER_SOURCE_REVISION
    }
    /// Returns the exact source archive encoding.
    #[must_use]
    pub const fn archive_format(&self) -> &'static str {
        GITHUB_PROVIDER_ARCHIVE_FORMAT
    }
    /// Returns the pinned bounded resource policy.
    #[must_use]
    pub const fn limits(&self) -> GithubProviderManifestLimits {
        self.limits
    }
    /// Returns the immutable manifest revision.
    #[must_use]
    pub const fn revision(&self) -> GithubProviderManifestRevision {
        self.revision
    }
    /// Returns the digest of every immutable manifest field.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) fn from_durable_parts(
        manifest: Self,
        expected_repository_id: RepositoryId,
        expected_digest: Sha256Digest,
    ) -> Result<Self, GithubProviderManifestValueError> {
        if manifest.repository_id != expected_repository_id || manifest.digest != expected_digest {
            return Err(GithubProviderManifestValueError::DurableManifestMismatch);
        }
        Ok(manifest)
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) fn same_connection_identity(&self, other: &Self) -> bool {
        self.tenant == other.tenant
            && self.repository_id == other.repository_id
            && self.connection_id == other.connection_id
            && self.installation_id == other.installation_id
            && self.installation_binding_generation == other.installation_binding_generation
            && self.github_repository_id == other.github_repository_id
            && self.github_repository_name == other.github_repository_name
            && self.github_app_id == other.github_app_id
            && self.app_client_id == other.app_client_id
            && self.jwt_issuer == other.jwt_issuer
            && self.origins == other.origins
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) fn valid_successor_of(&self, prior: &Self) -> bool {
        let Some(expected_revision) = prior.revision.get().checked_add(1) else {
            return false;
        };
        let app_evidence_changed = self.app_key_spki_sha256 != prior.app_key_spki_sha256;
        let verifier_evidence_changed =
            self.webhook_verifier_fingerprint != prior.webhook_verifier_fingerprint;
        let installation_changed = self.installation_id != prior.installation_id;
        let expected_installation_generation = if installation_changed {
            prior.installation_binding_generation.get().checked_add(1)
        } else {
            Some(prior.installation_binding_generation.get())
        };
        // The repository policy revision also versions the manifest-pinned
        // server-service authorities.  An authority implementation policy can
        // therefore rotate without changing another manifest field; the
        // strictly contiguous revision is the durable evidence for that
        // otherwise external policy transition.
        let policy_evidence_changed = self.policy_revision != prior.policy_revision
            || self.repository_visibility != prior.repository_visibility
            || self.github_repository_owner_id != prior.github_repository_owner_id
            || self.check_name != prior.check_name
            || self.workflow_selection != prior.workflow_selection
            || self.git_ref != prior.git_ref
            || self.check_subject_key != prior.check_subject_key
            || self.authority_profile != prior.authority_profile
            || self.runner_policy != prior.runner_policy
            || self.runtime_policy_digest != prior.runtime_policy_digest
            || self.limits != prior.limits;
        let runtime_policy_changed = self.runtime_policy_digest != prior.runtime_policy_digest;
        let expected_app_revision = if app_evidence_changed {
            prior.app_configuration_revision.get().checked_add(1)
        } else {
            Some(prior.app_configuration_revision.get())
        };
        let expected_verifier_revision = if verifier_evidence_changed {
            prior.webhook_verifier_revision.get().checked_add(1)
        } else {
            Some(prior.webhook_verifier_revision.get())
        };
        let expected_policy_revision = if policy_evidence_changed {
            prior.policy_revision.get().checked_add(1)
        } else {
            Some(prior.policy_revision.get())
        };
        let expected_runtime_policy_revision = if runtime_policy_changed {
            prior.runtime_policy_revision.get().checked_add(1)
        } else {
            Some(prior.runtime_policy_revision.get())
        };
        self.tenant == prior.tenant
            && self.repository_id == prior.repository_id
            && self.connection_id == prior.connection_id
            && self.github_repository_id == prior.github_repository_id
            && self.github_repository_name == prior.github_repository_name
            && self.github_app_id == prior.github_app_id
            && self.app_client_id == prior.app_client_id
            && self.jwt_issuer == prior.jwt_issuer
            && self.origins == prior.origins
            && expected_installation_generation == Some(self.installation_binding_generation.get())
            && self.revision.get() == expected_revision
            && (installation_changed
                || app_evidence_changed
                || verifier_evidence_changed
                || policy_evidence_changed)
            && expected_app_revision == Some(self.app_configuration_revision.get())
            && expected_verifier_revision == Some(self.webhook_verifier_revision.get())
            && expected_policy_revision == Some(self.policy_revision.get())
            && expected_runtime_policy_revision == Some(self.runtime_policy_revision.get())
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut digest = Sha256::new();
        digest.update(MANIFEST_DIGEST_DOMAIN);
        update_part(&mut digest, self.tenant.as_str().as_bytes());
        update_part(&mut digest, self.repository_id.as_uuid().as_bytes());
        update_part(&mut digest, self.connection_id.as_uuid().as_bytes());
        update_part(&mut digest, &self.installation_id.get().to_be_bytes());
        update_part(
            &mut digest,
            &self.installation_binding_generation.get().to_be_bytes(),
        );
        update_part(&mut digest, &self.github_repository_id.get().to_be_bytes());
        if let Some(owner_id) = self.github_repository_owner_id {
            update_part(&mut digest, &owner_id.get().to_be_bytes());
        }
        update_part(&mut digest, self.github_repository_name.as_str().as_bytes());
        update_part(
            &mut digest,
            self.repository_visibility().as_durable_str().as_bytes(),
        );
        update_part(&mut digest, &self.github_app_id.get().to_be_bytes());
        update_part(&mut digest, self.app_client_id.as_str().as_bytes());
        update_part(&mut digest, self.jwt_issuer.as_str().as_bytes());
        update_part(&mut digest, self.app_key_spki_sha256.as_bytes());
        update_part(
            &mut digest,
            &self.app_configuration_revision.get().to_be_bytes(),
        );
        update_part(
            &mut digest,
            self.webhook_verifier_fingerprint.sha256().as_bytes(),
        );
        update_part(
            &mut digest,
            &self.webhook_verifier_revision.get().to_be_bytes(),
        );
        update_part(&mut digest, &self.policy_revision.get().to_be_bytes());
        update_part(
            &mut digest,
            match self.authority_profile {
                JobAuthorityProfile::Standard => b"standard",
                JobAuthorityProfile::CredentialFree => b"credential_free",
            },
        );
        update_part(
            &mut digest,
            self.runner_policy.object().object_key().as_str().as_bytes(),
        );
        update_part(&mut digest, self.runner_policy.object().digest().as_bytes());
        update_part(
            &mut digest,
            &self.runner_policy.object().encoded_size().to_be_bytes(),
        );
        update_part(
            &mut digest,
            self.runner_policy.object().media_type().as_bytes(),
        );
        update_part(
            &mut digest,
            &self.runtime_policy_revision.get().to_be_bytes(),
        );
        update_part(&mut digest, self.runtime_policy_digest.as_bytes());
        update_part(&mut digest, &self.revision.get().to_be_bytes());
        update_part(&mut digest, self.workflow_path().as_bytes());
        update_part(
            &mut digest,
            self.workflow_selection.as_durable_str().as_bytes(),
        );
        update_part(&mut digest, self.event_name().as_bytes());
        update_part(&mut digest, self.git_ref().as_bytes());
        update_part(&mut digest, self.check_subject_key.as_str().as_bytes());
        update_part(&mut digest, self.check_name.as_str().as_bytes());
        update_part(&mut digest, self.origins.web_origin().as_bytes());
        update_part(&mut digest, self.origins.api_origin().as_bytes());
        update_part(&mut digest, self.origins.archive_origin().as_bytes());
        update_part(&mut digest, self.rest_api_version().as_bytes());
        update_part(&mut digest, self.rest_accept().as_bytes());
        update_part(&mut digest, self.archive_accept().as_bytes());
        update_part(&mut digest, self.source_authentication().as_bytes());
        update_part(&mut digest, self.source_revision().as_bytes());
        update_part(&mut digest, self.archive_format().as_bytes());
        for value in [
            self.limits.webhook_max_body_bytes(),
            self.limits.webhook_accept_timeout_millis(),
            self.limits.push_webhook_max_commits(),
            self.limits.path_filter_max_commits(),
            self.limits.path_filter_max_changed_files(),
            self.limits.archive_max_compressed_bytes(),
            self.limits.archive_max_decompressed_bytes(),
            self.limits.archive_max_entries(),
            self.limits.archive_max_expanded_bytes(),
            self.limits.archive_max_entry_path_bytes(),
            self.limits.archive_max_workflows(),
            self.limits.workflow_max_bytes(),
        ] {
            update_part(&mut digest, &value.to_be_bytes());
        }
        Sha256Digest::from_bytes(digest.finalize().into())
    }
}

/// Startup request to converge one exact desired provider revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapGithubProviderManifest {
    manifest: GithubProviderManifest,
    applied_at: UnixMillis,
}

/// One exact repository bootstrap pair committed under a single repository lock.
///
/// The canonical runner-policy object and repository semantic policy are two
/// distinct identities. This request proves that both describe the same typed
/// policy while retaining both identities in the historical manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapGithubProviderRepository {
    runtime_policy: RegisterWorkflowRuntimePolicy,
    manifest: BootstrapGithubProviderManifest,
}

impl BootstrapGithubProviderRepository {
    /// Constructs one exact, atomically applied policy/manifest pair.
    ///
    /// # Errors
    ///
    /// Rejects cross-repository pairs, mismatched repository pins, a manifest
    /// object that is not the canonical encoding of the typed policy, or two
    /// different caller observations for one convergence operation.
    pub fn new(
        runtime_policy: RegisterWorkflowRuntimePolicy,
        manifest: BootstrapGithubProviderManifest,
    ) -> Result<Self, GithubProviderManifestValueError> {
        let desired = manifest.manifest();
        let pin = runtime_policy.pin();
        let canonical = runtime_policy
            .policy()
            .canonical_bytes()
            .map_err(|_| GithubProviderManifestValueError::DurableManifestMismatch)?;
        if pin.tenant() != desired.tenant()
            || pin.repository_id() != desired.repository_id()
            || pin.revision() != desired.runtime_policy_revision()
            || pin.digest() != desired.runtime_policy_digest()
            || runtime_policy.registered_at() != manifest.applied_at()
            || runtime_policy.policy().canonical_digest()
                != desired.runner_policy().object().digest()
            || u64::try_from(canonical.len()).ok()
                != Some(desired.runner_policy().object().encoded_size())
        {
            return Err(GithubProviderManifestValueError::DurableManifestMismatch);
        }
        Ok(Self {
            runtime_policy,
            manifest,
        })
    }

    /// Returns the exact repository policy registration.
    #[must_use]
    pub const fn runtime_policy(&self) -> &RegisterWorkflowRuntimePolicy {
        &self.runtime_policy
    }

    /// Returns the exact historical manifest convergence request.
    #[must_use]
    pub const fn manifest(&self) -> &BootstrapGithubProviderManifest {
        &self.manifest
    }
}

impl BootstrapGithubProviderManifest {
    /// Constructs a startup convergence request.
    ///
    /// # Errors
    ///
    /// Rejects a timestamp before the Unix epoch.
    pub fn new(
        manifest: GithubProviderManifest,
        applied_at: UnixMillis,
    ) -> Result<Self, GithubProviderManifestValueError> {
        if applied_at.get() < 0 {
            return Err(GithubProviderManifestValueError::NegativeTimestamp);
        }
        Ok(Self {
            manifest,
            applied_at,
        })
    }

    /// Returns the exact desired immutable manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GithubProviderManifest {
        &self.manifest
    }

    /// Returns the trusted convergence observation time.
    #[must_use]
    pub const fn applied_at(&self) -> UnixMillis {
        self.applied_at
    }
}

/// One readable immutable manifest revision and its current-pointer state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProviderManifestRecord {
    manifest: GithubProviderManifest,
    registered_at: UnixMillis,
    activated_at: Option<UnixMillis>,
}

impl GithubProviderManifestRecord {
    #[cfg(feature = "adapter-spi")]
    pub(crate) fn new(
        manifest: GithubProviderManifest,
        registered_at: UnixMillis,
        activated_at: Option<UnixMillis>,
    ) -> Result<Self, GithubProviderManifestValueError> {
        if registered_at.get() < 0
            || activated_at.is_some_and(|activated_at| activated_at != registered_at)
        {
            return Err(GithubProviderManifestValueError::InvalidDurableTime);
        }
        Ok(Self {
            manifest,
            registered_at,
            activated_at,
        })
    }

    /// Returns the immutable manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GithubProviderManifest {
        &self.manifest
    }
    /// Returns when this revision first entered the durable registry.
    #[must_use]
    pub const fn registered_at(&self) -> UnixMillis {
        self.registered_at
    }
    /// Returns the current activation time, or `None` for a historical revision.
    #[must_use]
    pub const fn activated_at(&self) -> Option<UnixMillis> {
        self.activated_at
    }
    /// Reports whether this exact revision is the current pointer target.
    #[must_use]
    pub const fn is_current(&self) -> bool {
        self.activated_at.is_some()
    }
}

/// Result of startup convergence on one replica.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProviderManifestBootstrapReceipt {
    current: GithubProviderManifestRecord,
    replay: bool,
}

/// Exact receipts from one atomic repository policy/manifest convergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProviderRepositoryBootstrapReceipt {
    runtime_policy: WorkflowRuntimePolicyReceipt,
    manifest: GithubProviderManifestBootstrapReceipt,
}

impl GithubProviderRepositoryBootstrapReceipt {
    #[cfg(feature = "adapter-spi")]
    pub(crate) fn new(
        runtime_policy: WorkflowRuntimePolicyReceipt,
        manifest: GithubProviderManifestBootstrapReceipt,
    ) -> Result<Self, GithubProviderManifestValueError> {
        let desired = manifest.current().manifest();
        if runtime_policy.pin().tenant() != desired.tenant()
            || runtime_policy.pin().repository_id() != desired.repository_id()
            || runtime_policy.pin().revision() != desired.runtime_policy_revision()
            || runtime_policy.pin().digest() != desired.runtime_policy_digest()
        {
            return Err(GithubProviderManifestValueError::DurableManifestMismatch);
        }
        Ok(Self {
            runtime_policy,
            manifest,
        })
    }

    /// Returns the exact repository runtime-policy receipt.
    #[must_use]
    pub const fn runtime_policy(&self) -> &WorkflowRuntimePolicyReceipt {
        &self.runtime_policy
    }

    /// Returns the exact historical provider-manifest receipt.
    #[must_use]
    pub const fn manifest(&self) -> &GithubProviderManifestBootstrapReceipt {
        &self.manifest
    }
}

impl GithubProviderManifestBootstrapReceipt {
    #[cfg(feature = "adapter-spi")]
    pub(crate) fn new(
        current: GithubProviderManifestRecord,
        replay: bool,
    ) -> Result<Self, GithubProviderManifestValueError> {
        if !current.is_current() {
            return Err(GithubProviderManifestValueError::DurableManifestMismatch);
        }
        Ok(Self { current, replay })
    }

    /// Returns the exact current durable record.
    #[must_use]
    pub const fn current(&self) -> &GithubProviderManifestRecord {
        &self.current
    }
    /// Reports whether another replica had already applied these exact bytes.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

/// Portable provider-manifest persistence failures.
#[derive(Debug, Error)]
pub enum GithubProviderManifestStoreError {
    /// Backend operation failed behind a sanitized boundary.
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    /// Existing durable state disagrees with the exact desired configuration.
    #[error("GitHub provider manifest conflicts with durable configuration")]
    ConfigurationDrift,
    /// A manifest revision must advance before numeric owner evidence changes.
    #[error("GitHub provider owner binding requires the next manifest and policy revisions")]
    OwnerBindingRevisionRequired,
    /// Durable data violates the current-only manifest contract.
    #[error("durable GitHub provider manifest data is corrupt")]
    CorruptData,
    /// The requested current or historical revision does not exist.
    #[error("GitHub provider manifest was not found")]
    NotFound,
}

impl GithubProviderManifestStoreError {
    /// Wraps a backend failure without exposing provider configuration values.
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }
}

/// Value-construction failures for the non-secret manifest boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubProviderManifestValueError {
    /// Manifest revision is zero or outside the durable range.
    #[error("GitHub provider manifest revision is invalid")]
    InvalidRevision,
    /// Installation binding generation is zero or outside the durable range.
    #[error("GitHub installation binding generation is invalid")]
    InvalidInstallationBindingGeneration,
    /// The selected full default-branch ref is not canonical.
    #[error("GitHub provider manifest Git ref is invalid")]
    InvalidGitRef,
    /// Resource policy is incoherent or outside its fixed bound.
    #[error("GitHub provider manifest limits are invalid")]
    InvalidLimits,
    /// Webhook verifier evidence uses the reserved non-fingerprint sentinel.
    #[error("GitHub provider webhook verifier fingerprint is invalid")]
    InvalidWebhookVerifierFingerprint,
    /// The runner-policy object is absent, excessive, or has the wrong media type.
    #[error("GitHub provider runner-policy object is invalid")]
    InvalidRunnerPolicyObject,
    /// Startup observation predates the Unix epoch.
    #[error("GitHub provider manifest timestamp is negative")]
    NegativeTimestamp,
    /// Durable registration/current time evidence is incoherent.
    #[error("GitHub provider manifest durable time is invalid")]
    InvalidDurableTime,
    /// Rehydrated durable identity or digest disagrees with canonical derivation.
    #[error("GitHub provider manifest durable identity is invalid")]
    DurableManifestMismatch,
}

/// Startup and read boundary for immutable provider-manifest revisions.
#[async_trait]
pub trait GithubProviderManifestRepository: Send + Sync {
    /// Atomically registers/selects one repository policy and the exact
    /// historical manifest that names it.
    async fn bootstrap_github_provider_repository(
        &self,
        request: BootstrapGithubProviderRepository,
    ) -> Result<GithubProviderRepositoryBootstrapReceipt, GithubProviderManifestStoreError>;

    /// Loads the exact current revision for one tenant and connection.
    async fn load_current_github_provider_manifest(
        &self,
        tenant: &TenantScope,
        connection_id: ProviderConnectionId,
    ) -> Result<GithubProviderManifestRecord, GithubProviderManifestStoreError>;

    /// Lists a bounded, stable-order snapshot of every current GitHub manifest.
    ///
    /// This is a product-worker discovery boundary, not a mutable provider
    /// configuration API. Callers must still bind every subsequent side effect
    /// to the returned immutable manifest and let the destination repository
    /// re-check currentness under its own claim fence.
    async fn list_current_github_provider_manifests(
        &self,
        limit: u16,
    ) -> Result<Vec<GithubProviderManifestRecord>, GithubProviderManifestStoreError>;

    /// Loads one immutable current or historical revision.
    async fn load_github_provider_manifest_revision(
        &self,
        tenant: &TenantScope,
        connection_id: ProviderConnectionId,
        revision: GithubProviderManifestRevision,
    ) -> Result<GithubProviderManifestRecord, GithubProviderManifestStoreError>;
}

/// Derives the internal repository UUID used by ordinary workflow admission.
///
/// This duplicates no caller authority: tenant, provider name, and numeric
/// GitHub repository ID are the complete namespaced input.
#[must_use]
pub fn github_provider_repository_id(
    tenant: &TenantScope,
    github_repository_id: GithubRepositoryId,
) -> RepositoryId {
    let provider_repository_id = github_repository_id.get().to_string();
    let uuid = derived_uuid(
        REPOSITORY_ID_DOMAIN,
        &[
            tenant.as_str().as_bytes(),
            b"github",
            provider_repository_id.as_bytes(),
        ],
    );
    RepositoryId::from_uuid(uuid)
}

fn derived_uuid(domain: &[u8], components: &[&[u8]]) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        hasher.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(component);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn update_part(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn canonical_direct_workflow_path(value: &str) -> bool {
    let Some(file) = value.strip_prefix(".ci/workflows/") else {
        return false;
    };
    canonical_direct_workflow_file(file)
}

fn canonical_direct_workflow_file(file: &str) -> bool {
    let supported_extension = matches!(
        file.rsplit_once('.'),
        Some((stem, "yml" | "yaml")) if !stem.is_empty()
    );
    !file.is_empty()
        && !file.contains('/')
        && !file.contains('\\')
        && !file.chars().any(char::is_control)
        && supported_extension
}

fn canonical_branch_name(branch: &str) -> bool {
    !branch.is_empty()
        && branch != "@"
        && !branch.starts_with(['-', '/', '.'])
        && !branch.ends_with(['/', '.'])
        && !branch.contains("//")
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
        && branch.split('/').all(|component| {
            !component.starts_with('.') && !component.as_bytes().ends_with(b".lock")
        })
}

#[cfg(test)]
mod limit_contract_tests {
    use super::{
        GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES,
        GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES, GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES,
        GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES, GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES,
        GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS, GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES,
        GITHUB_PROVIDER_WORKFLOW_MAX_BYTES, GithubProviderManifestLimitRejection,
        archive_compressed_bytes_rejection, archive_decompressed_bytes_rejection,
        archive_entries_rejection, archive_entry_path_bytes_rejection,
        archive_expanded_bytes_rejection, archive_workflows_rejection,
        runner_policy_bytes_rejection, workflow_bytes_rejection,
    };

    #[test]
    fn runner_policy_bytes_has_exact_boundaries() {
        assert_eq!(
            runner_policy_bytes_rejection(GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES - 1),
            None
        );
        assert_eq!(
            runner_policy_bytes_rejection(GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES),
            None
        );
        assert_eq!(
            runner_policy_bytes_rejection(GITHUB_PROVIDER_RUNNER_POLICY_MAX_BYTES + 1),
            Some(GithubProviderManifestLimitRejection::RunnerPolicyBytes)
        );
    }

    #[test]
    fn archive_compressed_bytes_has_exact_boundaries() {
        assert_eq!(
            archive_compressed_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES - 1),
            None
        );
        assert_eq!(
            archive_compressed_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES),
            None
        );
        assert_eq!(
            archive_compressed_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_COMPRESSED_BYTES + 1),
            Some(GithubProviderManifestLimitRejection::ArchiveCompressedBytes)
        );
    }

    #[test]
    fn archive_decompressed_bytes_has_exact_boundaries() {
        assert_eq!(
            archive_decompressed_bytes_rejection(
                GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES - 1,
            ),
            None
        );
        assert_eq!(
            archive_decompressed_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES),
            None
        );
        assert_eq!(
            archive_decompressed_bytes_rejection(
                GITHUB_PROVIDER_ARCHIVE_MAX_DECOMPRESSED_BYTES + 1,
            ),
            Some(GithubProviderManifestLimitRejection::ArchiveDecompressedBytes)
        );
    }

    #[test]
    fn archive_entries_has_exact_boundaries() {
        assert_eq!(
            archive_entries_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES - 1),
            None
        );
        assert_eq!(
            archive_entries_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES),
            None
        );
        assert_eq!(
            archive_entries_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_ENTRIES + 1),
            Some(GithubProviderManifestLimitRejection::ArchiveEntries)
        );
    }

    #[test]
    fn archive_expanded_bytes_has_exact_boundaries() {
        assert_eq!(
            archive_expanded_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES - 1),
            None
        );
        assert_eq!(
            archive_expanded_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES),
            None
        );
        assert_eq!(
            archive_expanded_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_EXPANDED_BYTES + 1),
            Some(GithubProviderManifestLimitRejection::ArchiveExpandedBytes)
        );
    }

    #[test]
    fn archive_entry_path_bytes_has_exact_boundaries() {
        assert_eq!(
            archive_entry_path_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES - 1),
            None
        );
        assert_eq!(
            archive_entry_path_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES),
            None
        );
        assert_eq!(
            archive_entry_path_bytes_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_ENTRY_PATH_BYTES + 1),
            Some(GithubProviderManifestLimitRejection::ArchiveEntryPathBytes)
        );
    }

    #[test]
    fn archive_workflows_has_exact_boundaries() {
        assert_eq!(
            archive_workflows_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS - 1),
            None
        );
        assert_eq!(
            archive_workflows_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS),
            None
        );
        assert_eq!(
            archive_workflows_rejection(GITHUB_PROVIDER_ARCHIVE_MAX_WORKFLOWS + 1),
            Some(GithubProviderManifestLimitRejection::ArchiveWorkflows)
        );
    }

    #[test]
    fn workflow_bytes_has_exact_boundaries() {
        assert_eq!(
            workflow_bytes_rejection(GITHUB_PROVIDER_WORKFLOW_MAX_BYTES - 1),
            None
        );
        assert_eq!(
            workflow_bytes_rejection(GITHUB_PROVIDER_WORKFLOW_MAX_BYTES),
            None
        );
        assert_eq!(
            workflow_bytes_rejection(GITHUB_PROVIDER_WORKFLOW_MAX_BYTES + 1),
            Some(GithubProviderManifestLimitRejection::WorkflowBytes)
        );
    }
}
