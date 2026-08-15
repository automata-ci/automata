//! Durable provenance for GitHub's effective repository workflow-permission defaults.

use async_trait::async_trait;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_github_permissions::GithubDefaultWorkflowPermission;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    BootstrapGithubProviderRepository, GITHUB_PROVIDER_REST_API_VERSION, GithubProviderManifest,
    GithubProviderManifestRevision, GithubRepositoryName, GithubServerServiceAction,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceConsumerId, GithubServerServiceGeneration,
    GithubServerServiceHandoffId, GithubServerServiceJwtIssuer, GithubServerServiceRevision,
    GithubServerServiceScope, GithubServerServiceWorkerId,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, ProviderConnectionId, ProviderInstallationId,
    ProviderRepositoryId, ReleaseGithubServerServiceHandoff, RepositoryId, TenantScope,
    WorkflowRuntimePolicyRevision,
};

const CANDIDATE_SCHEMA: u16 = 2;
const OBSERVATION_SCHEMA: u16 = 2;
const OBSERVATION_FINALIZE_MARGIN_MILLIS: i64 = 60 * 1_000;
const CANDIDATE_DIGEST_DOMAIN: &[u8] = b"automata.store.github-workflow-permission-candidate.v2\0";
const OBSERVATION_DIGEST_DOMAIN: &[u8] = b"automata.store.github-workflow-permission-defaults.v2\0";

/// Maximum age of one authenticated repository workflow-permission observation.
///
/// New workflow admissions fail closed after this horizon. Product maintenance
/// refreshes the observation before half of the interval elapses.
pub const GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS: i64 = 15 * 60 * 1_000;

/// Immutable, non-current candidate that authorizes one exact observation attempt.
///
/// A candidate is deliberately separate from canonical runtime-policy and
/// provider-manifest revisions. A rejected GitHub setting therefore cannot
/// consume the next monotonic product revision or become current. The fresh
/// observation ID is also the handoff consumer ID, so every process restart
/// obtains a new durable natural key instead of attempting to reuse a released
/// handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubWorkflowPermissionObservationCandidate {
    observation_id: GithubServerServiceConsumerId,
    tenant: TenantScope,
    repository_id: RepositoryId,
    connection_id: ProviderConnectionId,
    manifest_revision: GithubProviderManifestRevision,
    manifest_digest: Sha256Digest,
    runtime_policy_revision: WorkflowRuntimePolicyRevision,
    runtime_policy_digest: Sha256Digest,
    installation_id: ProviderInstallationId,
    github_repository_id: ProviderRepositoryId,
    github_repository_name: GithubRepositoryName,
    github_app_id: GithubServerServiceAppId,
    github_app_client_id: GithubServerServiceAppClientId,
    github_app_jwt_issuer: GithubServerServiceJwtIssuer,
    app_key_spki_sha256: Sha256Digest,
    app_configuration_revision: GithubServerServiceRevision,
    policy_revision: GithubServerServiceRevision,
    authority_selector: GithubServerServiceAuthoritySelector,
    authority_identity_digest: Sha256Digest,
    expected_default: GithubDefaultWorkflowPermission,
    expected_can_approve_pull_request_reviews: bool,
    consumer: GithubServerServiceConsumerClaim,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
    digest: Sha256Digest,
}

impl GithubWorkflowPermissionObservationCandidate {
    /// Constructs one fresh observation candidate from an exact not-yet-current bootstrap pair.
    ///
    /// # Errors
    ///
    /// Rejects a cross-manifest authority, invalid timestamps, or numeric
    /// identities that cannot be represented by the handoff contract.
    pub fn new(
        bootstrap: &BootstrapGithubProviderRepository,
        authority: &GithubServerServiceAuthorityIdentity,
        observation_id: GithubServerServiceConsumerId,
        owner: GithubServerServiceWorkerId,
        claimed_at: UnixMillis,
    ) -> Result<Self, GithubWorkflowPermissionDefaultsObservationError> {
        let manifest = bootstrap.manifest().manifest();
        if claimed_at.get() < 0 || !authority_matches_manifest(authority, manifest) {
            return Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding);
        }
        let expires_at = claimed_at
            .get()
            .checked_add(
                MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS + OBSERVATION_FINALIZE_MARGIN_MILLIS,
            )
            .map(UnixMillis::new)
            .ok_or(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)?;
        let fence = GithubServerServiceClaimFence::new(manifest.revision().get())
            .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)?;
        let revision =
            GithubServerServiceRevision::new(manifest.runtime_policy_revision().get())
                .map_err(|_| GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)?;
        let consumer = GithubServerServiceConsumerClaim::new(
            observation_id,
            owner,
            fence,
            GithubServerServiceAction::ObserveWorkflowPermissionDefaults,
            revision,
        );
        let expected_default = bootstrap
            .runtime_policy()
            .policy()
            .permission_policy()
            .github_default();
        let mut candidate = Self {
            observation_id,
            tenant: manifest.tenant().clone(),
            repository_id: manifest.repository_id(),
            connection_id: manifest.connection_id(),
            manifest_revision: manifest.revision(),
            manifest_digest: manifest.digest(),
            runtime_policy_revision: manifest.runtime_policy_revision(),
            runtime_policy_digest: manifest.runtime_policy_digest(),
            installation_id: manifest.installation_id(),
            github_repository_id: manifest.github_repository_id(),
            github_repository_name: manifest.github_repository_name().clone(),
            github_app_id: manifest.github_app_id(),
            github_app_client_id: manifest.app_client_id().clone(),
            github_app_jwt_issuer: manifest.jwt_issuer(),
            app_key_spki_sha256: manifest.app_key_spki_sha256(),
            app_configuration_revision: manifest.app_configuration_revision(),
            policy_revision: manifest.policy_revision(),
            authority_selector: GithubServerServiceAuthoritySelector::from_identity(authority),
            authority_identity_digest: authority.identity_digest(),
            expected_default,
            expected_can_approve_pull_request_reviews: false,
            consumer,
            claimed_at,
            expires_at,
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        candidate.digest = candidate.compute_digest();
        Ok(candidate)
    }

    #[must_use]
    pub const fn observation_id(&self) -> GithubServerServiceConsumerId {
        self.observation_id
    }
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }
    #[must_use]
    pub const fn manifest_revision(&self) -> GithubProviderManifestRevision {
        self.manifest_revision
    }
    #[must_use]
    pub const fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }
    #[must_use]
    pub const fn runtime_policy_revision(&self) -> WorkflowRuntimePolicyRevision {
        self.runtime_policy_revision
    }
    #[must_use]
    pub const fn runtime_policy_digest(&self) -> Sha256Digest {
        self.runtime_policy_digest
    }
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.installation_id
    }
    #[must_use]
    pub const fn github_repository_id(&self) -> ProviderRepositoryId {
        self.github_repository_id
    }
    #[must_use]
    pub const fn github_repository_name(&self) -> &GithubRepositoryName {
        &self.github_repository_name
    }
    #[must_use]
    pub const fn github_app_id(&self) -> GithubServerServiceAppId {
        self.github_app_id
    }
    #[must_use]
    pub const fn github_app_client_id(&self) -> &GithubServerServiceAppClientId {
        &self.github_app_client_id
    }
    #[must_use]
    pub const fn github_app_jwt_issuer(&self) -> GithubServerServiceJwtIssuer {
        self.github_app_jwt_issuer
    }
    #[must_use]
    pub const fn app_key_spki_sha256(&self) -> Sha256Digest {
        self.app_key_spki_sha256
    }
    #[must_use]
    pub const fn app_configuration_revision(&self) -> GithubServerServiceRevision {
        self.app_configuration_revision
    }
    #[must_use]
    pub const fn policy_revision(&self) -> GithubServerServiceRevision {
        self.policy_revision
    }
    #[must_use]
    pub const fn authority_selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.authority_selector
    }
    #[must_use]
    pub const fn authority_identity_digest(&self) -> Sha256Digest {
        self.authority_identity_digest
    }
    #[must_use]
    pub const fn expected_default(&self) -> GithubDefaultWorkflowPermission {
        self.expected_default
    }
    /// Returns the least-authority repository PR-approval setting required by
    /// this policy. Workflow permissions are not current unless GitHub reports
    /// this exact value as well as the read/write default.
    #[must_use]
    pub const fn expected_can_approve_pull_request_reviews(&self) -> bool {
        self.expected_can_approve_pull_request_reviews
    }
    #[must_use]
    pub const fn consumer(&self) -> GithubServerServiceConsumerClaim {
        self.consumer
    }
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    fn matches_bootstrap(&self, bootstrap: &BootstrapGithubProviderRepository) -> bool {
        let manifest = bootstrap.manifest().manifest();
        self.tenant == *manifest.tenant()
            && self.repository_id == manifest.repository_id()
            && self.connection_id == manifest.connection_id()
            && self.manifest_revision == manifest.revision()
            && self.manifest_digest == manifest.digest()
            && self.runtime_policy_revision == manifest.runtime_policy_revision()
            && self.runtime_policy_digest == manifest.runtime_policy_digest()
            && self.expected_default
                == bootstrap
                    .runtime_policy()
                    .policy()
                    .permission_policy()
                    .github_default()
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut digest = Sha256::new();
        digest.update(CANDIDATE_DIGEST_DOMAIN);
        digest.update(CANDIDATE_SCHEMA.to_be_bytes());
        update_text(&mut digest, self.tenant.as_str());
        digest.update(self.observation_id.as_uuid().as_bytes());
        digest.update(self.repository_id.as_uuid().as_bytes());
        digest.update(self.connection_id.as_uuid().as_bytes());
        digest.update(self.manifest_revision.get().to_be_bytes());
        digest.update(self.manifest_digest.as_bytes());
        digest.update(self.runtime_policy_revision.get().to_be_bytes());
        digest.update(self.runtime_policy_digest.as_bytes());
        digest.update(self.installation_id.get().to_be_bytes());
        digest.update(self.github_repository_id.get().to_be_bytes());
        update_text(&mut digest, self.github_repository_name.as_str());
        digest.update(self.github_app_id.get().to_be_bytes());
        update_text(&mut digest, self.github_app_client_id.as_str());
        update_text(&mut digest, self.github_app_jwt_issuer.as_str());
        digest.update(self.app_key_spki_sha256.as_bytes());
        digest.update(self.app_configuration_revision.get().to_be_bytes());
        digest.update(self.policy_revision.get().to_be_bytes());
        digest.update(self.authority_selector.authority_id().as_uuid().as_bytes());
        digest.update(self.authority_identity_digest.as_bytes());
        update_text(&mut digest, self.expected_default.as_str());
        digest.update([u8::from(
            self.expected_can_approve_pull_request_reviews,
        )]);
        digest.update(self.consumer.consumer_id().as_uuid().as_bytes());
        digest.update(self.consumer.owner().as_uuid().as_bytes());
        digest.update(self.consumer.fence().get().to_be_bytes());
        update_text(&mut digest, self.consumer.action().as_str());
        digest.update(self.consumer.revision().get().to_be_bytes());
        digest.update(self.claimed_at.get().to_be_bytes());
        digest.update(self.expires_at.get().to_be_bytes());
        Sha256Digest::from_bytes(digest.finalize().into())
    }
}

/// Immutable result of one authenticated GitHub defaults request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubWorkflowPermissionDefaultsObservation {
    candidate: GithubWorkflowPermissionObservationCandidate,
    handoff_id: GithubServerServiceHandoffId,
    handoff_generation: GithubServerServiceGeneration,
    default_workflow_permissions: GithubDefaultWorkflowPermission,
    can_approve_pull_request_reviews: bool,
    provider_observed_at: UnixMillis,
    released_at: UnixMillis,
    digest: Sha256Digest,
}

impl GithubWorkflowPermissionDefaultsObservation {
    /// Constructs evidence bound to the exact candidate, handoff, and release.
    ///
    /// # Errors
    ///
    /// Rejects a release from any other authority/consumer or a completion
    /// outside the candidate's bounded provider-I/O window.
    pub fn new(
        bootstrap: &BootstrapGithubProviderRepository,
        candidate: GithubWorkflowPermissionObservationCandidate,
        release: &ReleaseGithubServerServiceHandoff,
        handoff_generation: GithubServerServiceGeneration,
        default_workflow_permissions: GithubDefaultWorkflowPermission,
        can_approve_pull_request_reviews: bool,
        provider_observed_at: UnixMillis,
    ) -> Result<Self, GithubWorkflowPermissionDefaultsObservationError> {
        if !candidate.matches_bootstrap(bootstrap)
            || release.selector() != candidate.authority_selector()
            || release.handoff_id().as_uuid().is_nil()
            || release.consumer() != candidate.consumer()
            || provider_observed_at < candidate.claimed_at()
            || provider_observed_at > release.released_at()
            || release.released_at() > candidate.expires_at()
        {
            return Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding);
        }
        let mut observation = Self {
            candidate,
            handoff_id: release.handoff_id(),
            handoff_generation,
            default_workflow_permissions,
            can_approve_pull_request_reviews,
            provider_observed_at,
            released_at: release.released_at(),
            digest: Sha256Digest::from_bytes([0; 32]),
        };
        observation.digest = observation.compute_digest();
        Ok(observation)
    }

    #[must_use]
    pub const fn candidate(&self) -> &GithubWorkflowPermissionObservationCandidate {
        &self.candidate
    }
    #[must_use]
    pub const fn handoff_id(&self) -> GithubServerServiceHandoffId {
        self.handoff_id
    }
    #[must_use]
    pub const fn handoff_generation(&self) -> GithubServerServiceGeneration {
        self.handoff_generation
    }
    #[must_use]
    pub const fn default_workflow_permissions(&self) -> GithubDefaultWorkflowPermission {
        self.default_workflow_permissions
    }
    #[must_use]
    pub const fn can_approve_pull_request_reviews(&self) -> bool {
        self.can_approve_pull_request_reviews
    }
    #[must_use]
    pub const fn provider_observed_at(&self) -> UnixMillis {
        self.provider_observed_at
    }
    #[must_use]
    pub const fn released_at(&self) -> UnixMillis {
        self.released_at
    }
    #[must_use]
    pub fn matches_expected_default(&self) -> bool {
        self.default_workflow_permissions == self.candidate.expected_default
            && self.can_approve_pull_request_reviews
                == self.candidate.expected_can_approve_pull_request_reviews
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut digest = Sha256::new();
        digest.update(OBSERVATION_DIGEST_DOMAIN);
        digest.update(OBSERVATION_SCHEMA.to_be_bytes());
        digest.update(self.candidate.observation_id.as_uuid().as_bytes());
        digest.update(self.candidate.digest.as_bytes());
        digest.update(self.handoff_id.as_uuid().as_bytes());
        digest.update(self.handoff_generation.get().to_be_bytes());
        update_text(&mut digest, GITHUB_PROVIDER_REST_API_VERSION);
        update_text(&mut digest, self.default_workflow_permissions.as_str());
        digest.update([u8::from(self.can_approve_pull_request_reviews)]);
        digest.update([u8::from(self.matches_expected_default())]);
        digest.update(self.provider_observed_at.get().to_be_bytes());
        digest.update(self.released_at.get().to_be_bytes());
        Sha256Digest::from_bytes(digest.finalize().into())
    }
}

/// Atomic release/evidence/activation request for one observation candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeGithubWorkflowPermissionObservation {
    bootstrap: BootstrapGithubProviderRepository,
    release: ReleaseGithubServerServiceHandoff,
    observation: GithubWorkflowPermissionDefaultsObservation,
}

/// Exact value-free request that closes an ambiguous observation handoff.
///
/// The complete immutable candidate is retained so storage can prove the
/// authority, consumer, digest, and provider-use horizon without retrying an
/// expired credential acquire or decrypting bearer material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileGithubWorkflowPermissionHandoff {
    candidate: GithubWorkflowPermissionObservationCandidate,
    required_through: UnixMillis,
}

impl ReconcileGithubWorkflowPermissionHandoff {
    /// Constructs the sole handoff horizon authorized by a candidate.
    ///
    /// # Errors
    ///
    /// Rejects timestamp overflow or a horizon outside the candidate lease.
    pub fn new(
        candidate: GithubWorkflowPermissionObservationCandidate,
    ) -> Result<Self, GithubWorkflowPermissionDefaultsObservationError> {
        let required_through = candidate
            .claimed_at()
            .get()
            .checked_add(candidate.consumer().action().provider_tail_millis())
            .map(UnixMillis::new)
            .ok_or(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding)?;
        if required_through >= candidate.expires_at() {
            return Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding);
        }
        Ok(Self {
            candidate,
            required_through,
        })
    }

    /// Returns the exact immutable candidate.
    #[must_use]
    pub const fn candidate(&self) -> &GithubWorkflowPermissionObservationCandidate {
        &self.candidate
    }

    /// Returns the original exclusive provider-use horizon.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }
}

/// Durable result of closing one ambiguous observation handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubWorkflowPermissionHandoffReconciliation {
    /// Storage proved that no natural-key handoff was ever committed and sealed
    /// the candidate against any later insert.
    AbsentClosed {
        /// Database-authoritative closure time.
        closed_at: UnixMillis,
    },
    /// Storage found a live handoff and atomically released it.
    Released {
        /// Durable natural-key winner.
        handoff_id: GithubServerServiceHandoffId,
        /// Borrowed protected issuance generation.
        generation: GithubServerServiceGeneration,
        /// Database-authoritative release time.
        released_at: UnixMillis,
    },
    /// Storage proved that the exact handoff had already been released.
    AlreadyReleased {
        /// Durable natural-key winner.
        handoff_id: GithubServerServiceHandoffId,
        /// Borrowed protected issuance generation.
        generation: GithubServerServiceGeneration,
        /// Existing immutable release time.
        released_at: UnixMillis,
    },
}

impl FinalizeGithubWorkflowPermissionObservation {
    /// Constructs an exact atomic finalization request.
    ///
    /// # Errors
    ///
    /// Rejects any disagreement between bootstrap, observation, and release.
    pub fn new(
        bootstrap: BootstrapGithubProviderRepository,
        release: ReleaseGithubServerServiceHandoff,
        observation: GithubWorkflowPermissionDefaultsObservation,
    ) -> Result<Self, GithubWorkflowPermissionDefaultsObservationError> {
        if !observation.candidate.matches_bootstrap(&bootstrap)
            || release.selector() != observation.candidate.authority_selector()
            || release.handoff_id() != observation.handoff_id
            || release.consumer() != observation.candidate.consumer
            || release.released_at() != observation.released_at
        {
            return Err(GithubWorkflowPermissionDefaultsObservationError::InvalidBinding);
        }
        Ok(Self {
            bootstrap,
            release,
            observation,
        })
    }

    #[must_use]
    pub const fn bootstrap(&self) -> &BootstrapGithubProviderRepository {
        &self.bootstrap
    }
    #[must_use]
    pub const fn release(&self) -> &ReleaseGithubServerServiceHandoff {
        &self.release
    }
    #[must_use]
    pub const fn observation(&self) -> &GithubWorkflowPermissionDefaultsObservation {
        &self.observation
    }
}

fn authority_matches_manifest(
    authority: &GithubServerServiceAuthorityIdentity,
    manifest: &GithubProviderManifest,
) -> bool {
    authority.scope() == GithubServerServiceScope::WorkflowPermissionsRead
        && authority.tenant() == manifest.tenant()
        && authority.repository_id() == manifest.repository_id()
        && authority.connection_id() == manifest.connection_id()
        && authority.installation_id() == manifest.installation_id()
        && authority.github_app_id() == manifest.github_app_id()
        && authority.github_repository_id() == manifest.github_repository_id()
        && authority.github_repository_name() == manifest.github_repository_name()
        && authority.app_client_id() == manifest.app_client_id()
        && authority.jwt_issuer() == manifest.jwt_issuer()
        && authority.app_key_spki_sha256() == manifest.app_key_spki_sha256()
        && authority.app_configuration_revision() == manifest.app_configuration_revision()
        && authority.policy_revision() == manifest.policy_revision()
}

fn update_text(digest: &mut Sha256, value: &str) {
    let length = u64::try_from(value.len()).expect("bounded durable text length fits u64");
    digest.update(length.to_be_bytes());
    digest.update(value.as_bytes());
}

/// Sanitized repository failure for workflow-permission observations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubWorkflowPermissionDefaultsObservationError {
    /// The candidate, observation, bootstrap, or release binding is invalid.
    #[error("the GitHub workflow-permission observation binding is invalid")]
    InvalidBinding,
    /// The database or storage operation is unavailable.
    #[error("the GitHub workflow-permission observation store is unavailable")]
    Operation,
    /// Existing immutable evidence conflicts with this request.
    #[error("the GitHub workflow-permission observation conflicts with durable evidence")]
    Conflict,
    /// Durable evidence is malformed or inconsistent.
    #[error("the GitHub workflow-permission observation is corrupt")]
    CorruptData,
}

/// Durable candidate and atomic observation-finalization repository.
#[async_trait]
pub trait GithubWorkflowPermissionDefaultsObservationRepository: Send + Sync {
    /// Creates only the exact tenant/repository identity needed before a staged authority exists.
    async fn prepare_github_workflow_permission_target(
        &self,
        manifest: &GithubProviderManifest,
    ) -> Result<(), GithubWorkflowPermissionDefaultsObservationError>;

    /// Persists one immutable, unexpired observation candidate.
    async fn claim_github_workflow_permission_observation(
        &self,
        candidate: GithubWorkflowPermissionObservationCandidate,
    ) -> Result<(), GithubWorkflowPermissionDefaultsObservationError>;

    /// Closes a possibly committed handoff without loading credential material.
    async fn reconcile_github_workflow_permission_handoff(
        &self,
        request: ReconcileGithubWorkflowPermissionHandoff,
    ) -> Result<
        GithubWorkflowPermissionHandoffReconciliation,
        GithubWorkflowPermissionDefaultsObservationError,
    >;

    /// Atomically releases the handoff, records evidence, and activates a
    /// matching canonical policy/manifest pair. A mismatch records evidence but
    /// leaves both canonical current pointers unchanged.
    async fn finalize_github_workflow_permission_observation(
        &self,
        request: FinalizeGithubWorkflowPermissionObservation,
    ) -> Result<bool, GithubWorkflowPermissionDefaultsObservationError>;
}
