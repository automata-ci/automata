//! Durable pre-resolution evidence for authenticated repository dispatches.
//!
//! GitHub's signed webhook names the default branch but does not carry the
//! immutable commit used by Actions. This boundary pins the raw delivery,
//! current provider manifest, and exact source authority before resolution.
//! A claimed worker later binds one provider-proven commit and creates the
//! queued Check before workflow admission can create a run.

use std::fmt;

use async_trait::async_trait;
use automata_ci_core::UnixMillis;
use thiserror::Error;

use crate::{
    AcceptProviderDelivery, AuthenticatedGithubDeliveryClaim, GithubAuthenticatedEvent,
    GithubAuthenticatedEventKind, GithubProviderManifest, GithubProviderWebhookVerifierFingerprint,
    GithubRepositoryDispatchResolution, GithubServerServiceAuthoritySelector,
    GithubServerServiceRevision, GithubSubjectEvidenceStoreError, GithubSubjectEvidenceValueError,
    ManifestPinnedGithubDeliveryEvidence, ProviderDeliveryId, ProviderRepositoryOwnerId,
    TenantScope,
};

/// Manifest and least-authority pins retained before default-branch resolution.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingGithubRepositoryDispatchEvidence {
    delivery_id: ProviderDeliveryId,
    repository_owner_id: ProviderRepositoryOwnerId,
    manifest: GithubProviderManifest,
    authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
    authenticated_webhook_verifier_revision: GithubServerServiceRevision,
    checks_authority: GithubServerServiceAuthoritySelector,
    repository_contents_authority: GithubServerServiceAuthoritySelector,
    event: GithubAuthenticatedEvent,
    accepted_at: UnixMillis,
}

impl PendingGithubRepositoryDispatchEvidence {
    /// Rehydrates one exact pending-resolution record.
    ///
    /// # Errors
    ///
    /// Rejects non-dispatch events, verifier drift, incoherent authority pins,
    /// or a pre-epoch acceptance time.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts(
        delivery_id: ProviderDeliveryId,
        repository_owner_id: ProviderRepositoryOwnerId,
        manifest: GithubProviderManifest,
        authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        authenticated_webhook_verifier_revision: GithubServerServiceRevision,
        checks_authority: GithubServerServiceAuthoritySelector,
        repository_contents_authority: GithubServerServiceAuthoritySelector,
        event: GithubAuthenticatedEvent,
        accepted_at: UnixMillis,
    ) -> Result<Self, GithubRepositoryDispatchValueError> {
        if accepted_at.get() < 0
            || event.kind() != GithubAuthenticatedEventKind::RepositoryDispatch
            || authenticated_webhook_verifier_fingerprint != manifest.webhook_verifier_fingerprint()
            || authenticated_webhook_verifier_revision != manifest.webhook_verifier_revision()
            || !selector_matches_manifest(&checks_authority, &manifest)
        {
            return Err(GithubRepositoryDispatchValueError);
        }
        if !selector_matches_manifest(&repository_contents_authority, &manifest)
            || repository_contents_authority.authority_id() == checks_authority.authority_id()
            || repository_contents_authority.identity_digest() == checks_authority.identity_digest()
        {
            return Err(GithubRepositoryDispatchValueError);
        }
        Ok(Self {
            delivery_id,
            repository_owner_id,
            manifest,
            authenticated_webhook_verifier_fingerprint,
            authenticated_webhook_verifier_revision,
            checks_authority,
            repository_contents_authority,
            event,
            accepted_at,
        })
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        self.manifest.tenant()
    }

    /// Returns the internal provider-inbox identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns the signed and configured numeric repository-owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the exact historical provider manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GithubProviderManifest {
        &self.manifest
    }

    /// Returns the public fingerprint of the webhook verifier.
    #[must_use]
    pub const fn authenticated_webhook_verifier_fingerprint(
        &self,
    ) -> GithubProviderWebhookVerifierFingerprint {
        self.authenticated_webhook_verifier_fingerprint
    }

    /// Returns the exact webhook-verifier policy revision.
    #[must_use]
    pub const fn authenticated_webhook_verifier_revision(&self) -> GithubServerServiceRevision {
        self.authenticated_webhook_verifier_revision
    }

    /// Returns the exact pinned Checks-write authority.
    #[must_use]
    pub const fn checks_authority(&self) -> &GithubServerServiceAuthoritySelector {
        &self.checks_authority
    }

    /// Returns the exact repository-contents authority.
    #[must_use]
    pub const fn repository_contents_authority(&self) -> &GithubServerServiceAuthoritySelector {
        &self.repository_contents_authority
    }

    /// Returns the authenticated event kind and default-branch ref.
    #[must_use]
    pub const fn event(&self) -> &GithubAuthenticatedEvent {
        &self.event
    }

    /// Returns the trusted inbox acceptance time.
    #[must_use]
    pub const fn accepted_at(&self) -> UnixMillis {
        self.accepted_at
    }
}

impl fmt::Debug for PendingGithubRepositoryDispatchEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingGithubRepositoryDispatchEvidence([REDACTED])")
    }
}

/// Immutable receipt for initial repository-dispatch persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingGithubRepositoryDispatchReceipt {
    evidence: PendingGithubRepositoryDispatchEvidence,
}

impl PendingGithubRepositoryDispatchReceipt {
    /// Rehydrates a receipt from fully checked pending evidence.
    #[must_use]
    pub const fn from_durable_parts(evidence: PendingGithubRepositoryDispatchEvidence) -> Self {
        Self { evidence }
    }

    /// Returns the complete pending-resolution evidence.
    #[must_use]
    pub const fn evidence(&self) -> &PendingGithubRepositoryDispatchEvidence {
        &self.evidence
    }

    /// Returns the durable provider-inbox identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.evidence.delivery_id()
    }
}

impl fmt::Debug for PendingGithubRepositoryDispatchReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingGithubRepositoryDispatchReceipt([REDACTED])")
    }
}

/// Initial manifest-pinned acceptance request for a custom repository dispatch.
pub struct AcceptManifestPinnedGithubRepositoryDispatch {
    delivery: AcceptProviderDelivery,
    repository_owner_id: ProviderRepositoryOwnerId,
    event: GithubAuthenticatedEvent,
    authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
    authenticated_webhook_verifier_revision: GithubServerServiceRevision,
}

impl AcceptManifestPinnedGithubRepositoryDispatch {
    /// Constructs a pre-resolution acceptance request.
    ///
    /// # Errors
    ///
    /// Rejects non-GitHub deliveries, mismatched owners, or a non-dispatch event.
    pub fn new(
        delivery: AcceptProviderDelivery,
        signed_repository_owner_id: ProviderRepositoryOwnerId,
        configured_repository_owner_id: ProviderRepositoryOwnerId,
        event: GithubAuthenticatedEvent,
        authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        authenticated_webhook_verifier_revision: GithubServerServiceRevision,
    ) -> Result<Self, GithubRepositoryDispatchValueError> {
        if delivery.identity().provider() != "github"
            || signed_repository_owner_id != configured_repository_owner_id
            || event.kind() != GithubAuthenticatedEventKind::RepositoryDispatch
        {
            return Err(GithubRepositoryDispatchValueError);
        }
        Ok(Self {
            delivery,
            repository_owner_id: signed_repository_owner_id,
            event,
            authenticated_webhook_verifier_fingerprint,
            authenticated_webhook_verifier_revision,
        })
    }

    /// Returns the exact generic provider-delivery acceptance request.
    #[must_use]
    pub const fn delivery(&self) -> &AcceptProviderDelivery {
        &self.delivery
    }

    /// Returns the signed and configured owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the authenticated default-branch event coordinates.
    #[must_use]
    pub const fn event(&self) -> &GithubAuthenticatedEvent {
        &self.event
    }

    /// Returns the exact verifier fingerprint.
    #[must_use]
    pub const fn authenticated_webhook_verifier_fingerprint(
        &self,
    ) -> GithubProviderWebhookVerifierFingerprint {
        self.authenticated_webhook_verifier_fingerprint
    }

    /// Returns the exact verifier policy revision.
    #[must_use]
    pub const fn authenticated_webhook_verifier_revision(&self) -> GithubServerServiceRevision {
        self.authenticated_webhook_verifier_revision
    }
}

impl fmt::Debug for AcceptManifestPinnedGithubRepositoryDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcceptManifestPinnedGithubRepositoryDispatch([REDACTED])")
    }
}

/// Claimed, exact default-branch resolution to bind before any workflow run.
pub struct ResolveGithubRepositoryDispatch {
    pending: PendingGithubRepositoryDispatchEvidence,
    claim: AuthenticatedGithubDeliveryClaim,
    resolution: GithubRepositoryDispatchResolution,
    observed_at: UnixMillis,
}

impl ResolveGithubRepositoryDispatch {
    /// Constructs a fenced resolution request.
    ///
    /// # Errors
    ///
    /// Rejects a foreign or expired claim.
    pub fn new(
        pending: PendingGithubRepositoryDispatchEvidence,
        claim: AuthenticatedGithubDeliveryClaim,
        resolution: GithubRepositoryDispatchResolution,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubRepositoryDispatchValueError> {
        if claim.claim().delivery_id() != pending.delivery_id() || !claim.authorizes(observed_at) {
            return Err(GithubRepositoryDispatchValueError);
        }
        Ok(Self {
            pending,
            claim,
            resolution,
            observed_at,
        })
    }

    /// Returns the exact pending manifest/authority evidence.
    #[must_use]
    pub const fn pending(&self) -> &PendingGithubRepositoryDispatchEvidence {
        &self.pending
    }

    /// Returns the current exact delivery claim.
    #[must_use]
    pub const fn claim(&self) -> AuthenticatedGithubDeliveryClaim {
        self.claim
    }

    /// Returns the immutable SHA and resolver mode.
    #[must_use]
    pub const fn resolution(&self) -> GithubRepositoryDispatchResolution {
        self.resolution
    }

    /// Returns the trusted resolution observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
}

impl fmt::Debug for ResolveGithubRepositoryDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResolveGithubRepositoryDispatch([REDACTED])")
    }
}

/// Invalid repository-dispatch evidence or transition request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub repository-dispatch evidence is invalid")]
pub struct GithubRepositoryDispatchValueError;

/// Durable repository for pending and resolved repository-dispatch evidence.
#[async_trait]
pub trait GithubRepositoryDispatchEvidenceRepository: Send + Sync {
    /// Atomically accepts raw event, current manifest, and resolver authority pins.
    async fn accept_manifest_pinned_github_repository_dispatch(
        &self,
        request: AcceptManifestPinnedGithubRepositoryDispatch,
    ) -> Result<PendingGithubRepositoryDispatchReceipt, GithubSubjectEvidenceStoreError>;

    /// Loads the immutable pre-resolution evidence for one exact delivery.
    async fn load_pending_github_repository_dispatch_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<PendingGithubRepositoryDispatchEvidence, GithubSubjectEvidenceStoreError>;

    /// Binds one resolved SHA and queues its Check under the current claim.
    async fn resolve_github_repository_dispatch(
        &self,
        request: ResolveGithubRepositoryDispatch,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError>;
}

fn selector_matches_manifest(
    selector: &GithubServerServiceAuthoritySelector,
    manifest: &GithubProviderManifest,
) -> bool {
    selector.tenant() == manifest.tenant()
        && selector.app_configuration_revision() == manifest.app_configuration_revision()
        && selector.policy_revision() == manifest.policy_revision()
}

impl From<GithubSubjectEvidenceValueError> for GithubRepositoryDispatchValueError {
    fn from(_: GithubSubjectEvidenceValueError) -> Self {
        Self
    }
}
