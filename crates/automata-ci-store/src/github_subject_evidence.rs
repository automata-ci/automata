//! Durable signed-owner evidence for GitHub workflow subjects.
//!
//! GitHub delivery acceptance is deliberately distinct from the generic
//! provider inbox port. One transaction pins the exact current provider
//! manifest, both required server-service authority selectors, and the
//! delivery's initial queued Check subject. A later logical-admission
//! transaction binds that exact Check and signed source evidence to one run.
//! Provider credentials and webhook bodies never enter this boundary.

use std::{fmt, num::NonZeroU16};

use async_trait::async_trait;
use automata_ci_core::{RunId, Sha256Digest, UnixMillis, WorkflowId};
use thiserror::Error;

use crate::{
    AcceptProviderDelivery, AdmitLogicalWorkflowRun, GithubCheckHeadSha, GithubCheckSubjectId,
    GithubCheckSubjectKey, GithubProviderManifest, GithubProviderManifestRevision,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName,
    GithubServerServiceAuthoritySelector, GithubServerServiceRevision, LogicalWorkflowInvocationId,
    MAX_PROVIDER_DELIVERY_ATTEMPTS, MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS, ProviderConnectionId,
    ProviderDeliveryClaimFence, ProviderDeliveryId, ProviderInstallationId, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, RepositoryId,
    RepositoryOperationError, TenantScope, WORKFLOW_PLAN_SCHEMA, WorkflowAdmissionIdempotency,
    WorkflowSnapshotId,
};

const MAX_EVIDENCE_TEXT_BYTES: usize = 1_024;

/// Closed event kind carried by a authenticated GitHub envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubAuthenticatedEventKind {
    /// A repository reference update.
    Push,
    /// Pull-request activity.
    PullRequest,
    /// Merge-queue group activity.
    MergeGroup,
    /// A custom repository-dispatch event.
    RepositoryDispatch,
}

impl GithubAuthenticatedEventKind {
    /// Returns the exact provider event-header spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::PullRequest => "pull_request",
            Self::MergeGroup => "merge_group",
            Self::RepositoryDispatch => "repository_dispatch",
        }
    }
}

/// Bounded selector coordinates for a authenticated GitHub event.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubAuthenticatedEvent {
    kind: GithubAuthenticatedEventKind,
    git_ref: Box<str>,
}

impl GithubAuthenticatedEvent {
    /// Constructs canonical event selector evidence.
    ///
    /// The worker later recomputes this ref from the exact rehydrated payload;
    /// this constructor only enforces the durable bounded full-ref shape.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, non-full, or control-bearing reference.
    pub fn new(
        kind: GithubAuthenticatedEventKind,
        git_ref: impl Into<Box<str>>,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        let git_ref = git_ref.into();
        if git_ref.len() < 6
            || git_ref.len() > MAX_EVIDENCE_TEXT_BYTES
            || !git_ref.starts_with("refs/")
            || git_ref.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(GithubSubjectEvidenceValueError::InvalidAuthenticatedEvent);
        }
        Ok(Self { kind, git_ref })
    }

    /// Returns the closed provider event kind.
    #[must_use]
    pub const fn kind(&self) -> GithubAuthenticatedEventKind {
        self.kind
    }

    /// Returns the exact full ref bound at authenticated ingress.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }
}

impl fmt::Debug for GithubAuthenticatedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAuthenticatedEvent")
            .field("kind", &self.kind)
            .field("git_ref", &"[REDACTED]")
            .finish()
    }
}

/// Least-authority mode that resolved a repository dispatch's default branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubRepositoryDispatchResolutionAuthority {
    /// The configured public repository was resolved without credentials.
    PublicAnonymous,
    /// The pinned exact-repository private-source authority performed resolution.
    PrivateSourceAuthority,
}

impl GithubRepositoryDispatchResolutionAuthority {
    /// Returns the closed durable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicAnonymous => "public_anonymous",
            Self::PrivateSourceAuthority => "private_source_authority",
        }
    }
}

/// Immutable source-resolution evidence for one custom repository dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubRepositoryDispatchResolution {
    source_revision: GithubCheckHeadSha,
    authority: GithubRepositoryDispatchResolutionAuthority,
}

impl GithubRepositoryDispatchResolution {
    /// Binds the exact default-branch commit to its least-authority mode.
    #[must_use]
    pub const fn new(
        source_revision: GithubCheckHeadSha,
        authority: GithubRepositoryDispatchResolutionAuthority,
    ) -> Self {
        Self {
            source_revision,
            authority,
        }
    }

    /// Returns the exact immutable default-branch commit.
    #[must_use]
    pub const fn source_revision(self) -> GithubCheckHeadSha {
        self.source_revision
    }

    /// Returns the exact resolver authority mode.
    #[must_use]
    pub const fn authority(self) -> GithubRepositoryDispatchResolutionAuthority {
        self.authority
    }
}

/// GitHub-only acceptance request carrying both signed and configured owner
/// identity plus the signed commit needed for the initial queued Check.
#[derive(Clone, Eq, PartialEq)]
pub struct AcceptManifestPinnedGithubDelivery {
    delivery: AcceptProviderDelivery,
    repository_owner_id: ProviderRepositoryOwnerId,
    head_sha: GithubCheckHeadSha,
    authenticated_event: GithubAuthenticatedEvent,
    authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
    authenticated_webhook_verifier_revision: GithubServerServiceRevision,
}

impl AcceptManifestPinnedGithubDelivery {
    /// Constructs one manifest-pinned GitHub acceptance request.
    ///
    /// The signed numeric owner and the server-configured numeric owner are
    /// deliberately separate inputs. They must agree before any durable write;
    /// the one retained value therefore proves both identities without a name
    /// fallback. The generic provider inbox remains owner-neutral.
    ///
    /// # Errors
    ///
    /// Rejects a non-GitHub identity or mismatched signed/configured owners.
    pub fn new(
        delivery: AcceptProviderDelivery,
        signed_repository_owner_id: ProviderRepositoryOwnerId,
        configured_repository_owner_id: ProviderRepositoryOwnerId,
        authenticated_event: GithubAuthenticatedEvent,
        head_sha: GithubCheckHeadSha,
        authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        authenticated_webhook_verifier_revision: GithubServerServiceRevision,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        if delivery.identity().provider() != "github" {
            return Err(GithubSubjectEvidenceValueError::NotGithub);
        }
        if signed_repository_owner_id != configured_repository_owner_id {
            return Err(GithubSubjectEvidenceValueError::RepositoryOwnerMismatch);
        }
        Ok(Self {
            delivery,
            repository_owner_id: signed_repository_owner_id,
            head_sha,
            authenticated_event,
            authenticated_webhook_verifier_fingerprint,
            authenticated_webhook_verifier_revision,
        })
    }

    /// Returns the authenticated provider delivery evidence.
    #[must_use]
    pub const fn delivery(&self) -> &AcceptProviderDelivery {
        &self.delivery
    }

    /// Returns the exact signed-and-configured positive owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the exact signed push head committed to the queued Check.
    #[must_use]
    pub const fn head_sha(&self) -> GithubCheckHeadSha {
        self.head_sha
    }

    /// Returns the authenticated event coordinates.
    #[must_use]
    pub const fn authenticated_event(&self) -> &GithubAuthenticatedEvent {
        &self.authenticated_event
    }

    /// Returns the public fingerprint of the exact HMAC key that authenticated
    /// this request.
    #[must_use]
    pub const fn authenticated_webhook_verifier_fingerprint(
        &self,
    ) -> GithubProviderWebhookVerifierFingerprint {
        self.authenticated_webhook_verifier_fingerprint
    }

    /// Returns the configured positive revision of that authenticated HMAC key.
    #[must_use]
    pub const fn authenticated_webhook_verifier_revision(&self) -> GithubServerServiceRevision {
        self.authenticated_webhook_verifier_revision
    }
}

impl fmt::Debug for AcceptManifestPinnedGithubDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcceptManifestPinnedGithubDelivery([REDACTED])")
    }
}

/// Immutable provider, signed-owner, Check, and service-authority evidence for
/// one GitHub inbox record.
#[derive(Clone, Eq, PartialEq)]
pub struct ManifestPinnedGithubDeliveryEvidence {
    delivery_id: ProviderDeliveryId,
    repository_owner_id: ProviderRepositoryOwnerId,
    manifest: GithubProviderManifest,
    authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
    authenticated_webhook_verifier_revision: GithubServerServiceRevision,
    checks_authority: GithubServerServiceAuthoritySelector,
    private_source_authority: Option<GithubServerServiceAuthoritySelector>,
    private_pull_request_files_authority: Option<GithubServerServiceAuthoritySelector>,
    check_subject_id: GithubCheckSubjectId,
    check_head_sha: GithubCheckHeadSha,
    authenticated_event: GithubAuthenticatedEvent,
    repository_dispatch_resolution: Option<GithubRepositoryDispatchResolution>,
    accepted_at: UnixMillis,
}

impl ManifestPinnedGithubDeliveryEvidence {
    /// Rehydrates one complete immutable GitHub delivery-evidence record.
    ///
    /// The manifest is the complete accepted policy, not merely a
    /// revision number. The mandatory `checks_write` selector and visibility-
    /// dependent private-source selector are retained exactly as accepted.
    /// Public evidence must prove that no private-source selector was pinned.
    ///
    /// # Errors
    ///
    /// Rejects selector/manifest drift, an invalid visibility-dependent private
    /// pin, reused authority IDs, or a pre-epoch acceptance time.
    #[allow(clippy::too_many_arguments)] // Every immutable delivery pin is explicit.
    pub fn from_durable_parts(
        delivery_id: ProviderDeliveryId,
        repository_owner_id: ProviderRepositoryOwnerId,
        manifest: GithubProviderManifest,
        authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        authenticated_webhook_verifier_revision: GithubServerServiceRevision,
        checks_authority: GithubServerServiceAuthoritySelector,
        private_source_authority: Option<GithubServerServiceAuthoritySelector>,
        check_subject_id: GithubCheckSubjectId,
        check_head_sha: GithubCheckHeadSha,
        authenticated_event: GithubAuthenticatedEvent,
        accepted_at: UnixMillis,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        Self::from_durable_parts_with_pull_request_files_authority(
            delivery_id,
            repository_owner_id,
            manifest,
            authenticated_webhook_verifier_fingerprint,
            authenticated_webhook_verifier_revision,
            checks_authority,
            private_source_authority,
            None,
            check_subject_id,
            check_head_sha,
            authenticated_event,
            accepted_at,
        )
    }

    /// Rehydrates evidence with an exact private pull-request-files authority pin.
    ///
    /// # Errors
    ///
    /// Rejects the same mismatches as [`Self::from_durable_parts`], plus a
    /// pull-request-files selector outside a private pull-request event or any
    /// selector identity reused by another authority.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts_with_pull_request_files_authority(
        delivery_id: ProviderDeliveryId,
        repository_owner_id: ProviderRepositoryOwnerId,
        manifest: GithubProviderManifest,
        authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        authenticated_webhook_verifier_revision: GithubServerServiceRevision,
        checks_authority: GithubServerServiceAuthoritySelector,
        private_source_authority: Option<GithubServerServiceAuthoritySelector>,
        private_pull_request_files_authority: Option<GithubServerServiceAuthoritySelector>,
        check_subject_id: GithubCheckSubjectId,
        check_head_sha: GithubCheckHeadSha,
        authenticated_event: GithubAuthenticatedEvent,
        accepted_at: UnixMillis,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        validate_timestamp(accepted_at)?;
        if authenticated_webhook_verifier_fingerprint != manifest.webhook_verifier_fingerprint()
            || authenticated_webhook_verifier_revision != manifest.webhook_verifier_revision()
        {
            return Err(GithubSubjectEvidenceValueError::WebhookVerifierPinMismatch);
        }
        if !selector_matches_manifest(&checks_authority, &manifest) {
            return Err(GithubSubjectEvidenceValueError::AuthorityPinMismatch);
        }
        match (manifest.repository_visibility(), &private_source_authority) {
            (ProviderRepositoryVisibility::Public, None) => {}
            (ProviderRepositoryVisibility::Private, Some(selector))
                if selector_matches_manifest(selector, &manifest)
                    && selector.authority_id() != checks_authority.authority_id()
                    && selector.identity_digest() != checks_authority.identity_digest() => {}
            _ => return Err(GithubSubjectEvidenceValueError::AuthorityPinMismatch),
        }
        match (
            manifest.repository_visibility(),
            authenticated_event.kind(),
            &private_pull_request_files_authority,
        ) {
            (ProviderRepositoryVisibility::Public, _, None)
            | (
                ProviderRepositoryVisibility::Private,
                GithubAuthenticatedEventKind::Push
                | GithubAuthenticatedEventKind::MergeGroup
                | GithubAuthenticatedEventKind::RepositoryDispatch,
                None,
            ) => {}
            (
                ProviderRepositoryVisibility::Private,
                GithubAuthenticatedEventKind::PullRequest,
                Some(selector),
            ) if selector_matches_manifest(selector, &manifest)
                && selector.authority_id() != checks_authority.authority_id()
                && selector.identity_digest() != checks_authority.identity_digest()
                && private_source_authority.as_ref().is_some_and(|source| {
                    selector.authority_id() != source.authority_id()
                        && selector.identity_digest() != source.identity_digest()
                }) => {}
            _ => return Err(GithubSubjectEvidenceValueError::AuthorityPinMismatch),
        }
        Ok(Self {
            delivery_id,
            repository_owner_id,
            manifest,
            authenticated_webhook_verifier_fingerprint,
            authenticated_webhook_verifier_revision,
            checks_authority,
            private_source_authority,
            private_pull_request_files_authority,
            check_subject_id,
            check_head_sha,
            authenticated_event,
            repository_dispatch_resolution: None,
            accepted_at,
        })
    }

    /// Rehydrates one fully resolved custom repository-dispatch delivery.
    ///
    /// # Errors
    ///
    /// Rejects a non-dispatch envelope, a source/Check mismatch, or a resolver
    /// authority mode inconsistent with the immutable repository visibility.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts_resolved_repository_dispatch(
        delivery_id: ProviderDeliveryId,
        repository_owner_id: ProviderRepositoryOwnerId,
        manifest: GithubProviderManifest,
        authenticated_webhook_verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
        authenticated_webhook_verifier_revision: GithubServerServiceRevision,
        checks_authority: GithubServerServiceAuthoritySelector,
        private_source_authority: Option<GithubServerServiceAuthoritySelector>,
        check_subject_id: GithubCheckSubjectId,
        check_head_sha: GithubCheckHeadSha,
        authenticated_event: GithubAuthenticatedEvent,
        resolution: GithubRepositoryDispatchResolution,
        accepted_at: UnixMillis,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        if authenticated_event.kind() != GithubAuthenticatedEventKind::RepositoryDispatch
            || resolution.source_revision() != check_head_sha
        {
            return Err(GithubSubjectEvidenceValueError::InvalidAuthenticatedEvent);
        }
        let expected_authority = match manifest.repository_visibility() {
            ProviderRepositoryVisibility::Public if private_source_authority.is_none() => {
                GithubRepositoryDispatchResolutionAuthority::PublicAnonymous
            }
            ProviderRepositoryVisibility::Private if private_source_authority.is_some() => {
                GithubRepositoryDispatchResolutionAuthority::PrivateSourceAuthority
            }
            _ => return Err(GithubSubjectEvidenceValueError::AuthorityPinMismatch),
        };
        if resolution.authority() != expected_authority {
            return Err(GithubSubjectEvidenceValueError::AuthorityPinMismatch);
        }
        let mut evidence = Self::from_durable_parts(
            delivery_id,
            repository_owner_id,
            manifest,
            authenticated_webhook_verifier_fingerprint,
            authenticated_webhook_verifier_revision,
            checks_authority,
            private_source_authority,
            check_subject_id,
            check_head_sha,
            authenticated_event,
            accepted_at,
        )?;
        evidence.repository_dispatch_resolution = Some(resolution);
        Ok(evidence)
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        self.manifest.tenant()
    }

    /// Returns the immutable inbox record identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns the internal repository pinned by the provider manifest.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.manifest.repository_id()
    }

    /// Returns the exact provider connection.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.manifest.connection_id()
    }

    /// Returns the exact GitHub App installation.
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.manifest.installation_id()
    }

    /// Returns the stable numeric GitHub repository identity.
    #[must_use]
    pub const fn github_repository_id(&self) -> ProviderRepositoryId {
        self.manifest.github_repository_id()
    }

    /// Returns the signed positive numeric GitHub owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the canonical case-sensitive `owner/repository` evidence.
    #[must_use]
    pub const fn github_repository_name(&self) -> &GithubRepositoryName {
        self.manifest.github_repository_name()
    }

    /// Returns the signed immutable repository visibility.
    #[must_use]
    pub const fn repository_visibility(&self) -> ProviderRepositoryVisibility {
        self.manifest.repository_visibility()
    }

    /// Returns the complete immutable historical provider policy.
    #[must_use]
    pub const fn manifest(&self) -> &GithubProviderManifest {
        &self.manifest
    }

    /// Returns the immutable provider-manifest revision.
    #[must_use]
    pub const fn manifest_revision(&self) -> GithubProviderManifestRevision {
        self.manifest.revision()
    }

    /// Returns the exact digest of the pinned provider manifest.
    #[must_use]
    pub const fn manifest_digest(&self) -> Sha256Digest {
        self.manifest.digest()
    }

    /// Returns the public fingerprint of the HMAC key that authenticated the
    /// delivery, exact-matched to the pinned manifest.
    #[must_use]
    pub const fn authenticated_webhook_verifier_fingerprint(
        &self,
    ) -> GithubProviderWebhookVerifierFingerprint {
        self.authenticated_webhook_verifier_fingerprint
    }

    /// Returns the authenticated key revision exact-matched to the manifest.
    #[must_use]
    pub const fn authenticated_webhook_verifier_revision(&self) -> GithubServerServiceRevision {
        self.authenticated_webhook_verifier_revision
    }

    /// Returns the exact pinned `checks_write` authority selector.
    #[must_use]
    pub const fn checks_authority(&self) -> &GithubServerServiceAuthoritySelector {
        &self.checks_authority
    }

    /// Returns the exact private-source selector; public evidence returns none.
    #[must_use]
    pub const fn private_source_authority(&self) -> Option<&GithubServerServiceAuthoritySelector> {
        self.private_source_authority.as_ref()
    }

    /// Returns the exact private pull-request-files selector when pinned.
    #[must_use]
    pub const fn private_pull_request_files_authority(
        &self,
    ) -> Option<&GithubServerServiceAuthoritySelector> {
        self.private_pull_request_files_authority.as_ref()
    }

    /// Returns the queued Check subject created at the same commit boundary.
    #[must_use]
    pub const fn check_subject_id(&self) -> GithubCheckSubjectId {
        self.check_subject_id
    }

    /// Returns the signed head retained by the exact queued Check.
    #[must_use]
    pub const fn check_head_sha(&self) -> GithubCheckHeadSha {
        self.check_head_sha
    }

    /// Returns the authenticated event coordinates.
    #[must_use]
    pub const fn authenticated_event(&self) -> &GithubAuthenticatedEvent {
        &self.authenticated_event
    }

    /// Returns immutable default-branch resolution evidence for repository dispatches.
    #[must_use]
    pub const fn repository_dispatch_resolution(
        &self,
    ) -> Option<GithubRepositoryDispatchResolution> {
        self.repository_dispatch_resolution
    }

    /// Returns the trusted inbox acceptance time.
    #[must_use]
    pub const fn accepted_at(&self) -> UnixMillis {
        self.accepted_at
    }
}

impl fmt::Debug for ManifestPinnedGithubDeliveryEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManifestPinnedGithubDeliveryEvidence([REDACTED])")
    }
}

/// Immutable acceptance receipt shared by initial commit and exact replay.
#[derive(Clone, Eq, PartialEq)]
pub struct ManifestPinnedGithubDeliveryReceipt {
    evidence: ManifestPinnedGithubDeliveryEvidence,
}

impl ManifestPinnedGithubDeliveryReceipt {
    /// Rehydrates a receipt from complete checked immutable evidence.
    #[must_use]
    pub fn from_durable_parts(evidence: ManifestPinnedGithubDeliveryEvidence) -> Self {
        Self { evidence }
    }

    /// Returns the complete immutable worker/admission evidence.
    #[must_use]
    pub const fn evidence(&self) -> &ManifestPinnedGithubDeliveryEvidence {
        &self.evidence
    }

    /// Returns the immutable inbox record identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.evidence.delivery_id()
    }

    /// Returns the queued Check subject created in the same transaction.
    #[must_use]
    pub const fn check_subject_id(&self) -> GithubCheckSubjectId {
        self.evidence.check_subject_id()
    }

    /// Returns the internal repository pinned by the provider manifest.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.evidence.repository_id()
    }

    /// Returns the signed positive numeric GitHub owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.evidence.repository_owner_id()
    }

    /// Returns the immutable provider-manifest revision.
    #[must_use]
    pub const fn manifest_revision(&self) -> GithubProviderManifestRevision {
        self.evidence.manifest_revision()
    }

    /// Returns the exact digest of the pinned provider manifest.
    #[must_use]
    pub const fn manifest_digest(&self) -> Sha256Digest {
        self.evidence.manifest_digest()
    }

    /// Returns the trusted inbox acceptance time.
    #[must_use]
    pub const fn accepted_at(&self) -> UnixMillis {
        self.evidence.accepted_at()
    }
}

impl fmt::Debug for ManifestPinnedGithubDeliveryReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManifestPinnedGithubDeliveryReceipt([REDACTED])")
    }
}

/// Exact durable provider-delivery claim authorizing GitHub logical admission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthenticatedGithubDeliveryClaim {
    claim: ProviderDeliveryClaimFence,
    attempt: NonZeroU16,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl AuthenticatedGithubDeliveryClaim {
    /// Constructs one bounded exact delivery-claim snapshot.
    ///
    /// # Errors
    ///
    /// Rejects an invalid attempt, pre-epoch time, or an empty/excessive total
    /// claim horizon. The repository additionally requires every field to match
    /// the record-locked current inbox claim before admission or replay.
    pub fn new(
        claim: ProviderDeliveryClaimFence,
        attempt: u16,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        let attempt = NonZeroU16::new(attempt)
            .filter(|attempt| attempt.get() <= MAX_PROVIDER_DELIVERY_ATTEMPTS)
            .ok_or(GithubSubjectEvidenceValueError::InvalidDeliveryClaim)?;
        validate_timestamp(claimed_at)?;
        validate_timestamp(expires_at)?;
        expires_at
            .get()
            .checked_sub(claimed_at.get())
            .filter(|duration| {
                *duration > 0 && *duration <= MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS
            })
            .ok_or(GithubSubjectEvidenceValueError::InvalidDeliveryClaim)?;
        Ok(Self {
            claim,
            attempt,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the durable delivery, owner, and positive claim fence.
    #[must_use]
    pub const fn claim(self) -> ProviderDeliveryClaimFence {
        self.claim
    }

    /// Returns the positive current processing attempt.
    #[must_use]
    pub const fn attempt(self) -> u16 {
        self.attempt.get()
    }

    /// Returns the immutable start of this processing attempt.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the exclusive current claim horizon.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }

    pub(crate) fn authorizes(self, observed_at: UnixMillis) -> bool {
        observed_at >= self.claimed_at && observed_at < self.expires_at
    }
}

impl fmt::Debug for AuthenticatedGithubDeliveryClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedGithubDeliveryClaim([REDACTED])")
    }
}

/// Exact logical-admission evidence used to create one immutable
/// GitHub workflow-run subject receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordGithubWorkflowRunSubjectEvidence {
    tenant: TenantScope,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    snapshot_id: WorkflowSnapshotId,
    run_id: RunId,
    root_invocation_id: LogicalWorkflowInvocationId,
    delivery_id: ProviderDeliveryId,
    provider_delivery_idempotency_key: String,
    admission_claim: AuthenticatedGithubDeliveryClaim,
    head_sha: GithubCheckHeadSha,
    workflow_path: GithubCheckSubjectKey,
    source_digest: Sha256Digest,
    event_name: String,
    event_digest: Sha256Digest,
    git_ref: String,
    plan_digest: Sha256Digest,
    logical_admission_digest: Sha256Digest,
    admitted_at: UnixMillis,
}

impl RecordGithubWorkflowRunSubjectEvidence {
    /// Constructs the exact evidence available at logical admission.
    ///
    /// `JobIR` is intentionally absent: concrete `JobIR` evidence is created
    /// later during materialization and must be joined independently by OIDC
    /// reservation/currentness checks.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, noncanonical event/ref text, or a pre-epoch
    /// admission time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
        snapshot_id: WorkflowSnapshotId,
        run_id: RunId,
        root_invocation_id: LogicalWorkflowInvocationId,
        delivery_id: ProviderDeliveryId,
        provider_delivery_idempotency_key: impl Into<String>,
        admission_claim: AuthenticatedGithubDeliveryClaim,
        head_sha: GithubCheckHeadSha,
        workflow_path: GithubCheckSubjectKey,
        source_digest: Sha256Digest,
        event_name: impl Into<String>,
        event_digest: Sha256Digest,
        git_ref: impl Into<String>,
        plan_digest: Sha256Digest,
        logical_admission_digest: Sha256Digest,
        admitted_at: UnixMillis,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        for (value, field) in [
            (
                repository_id.as_uuid(),
                "GitHub subject-evidence repository ID",
            ),
            (workflow_id.as_uuid(), "GitHub subject-evidence workflow ID"),
            (snapshot_id.as_uuid(), "GitHub subject-evidence snapshot ID"),
            (run_id.as_uuid(), "GitHub subject-evidence workflow run ID"),
            (
                root_invocation_id.as_uuid(),
                "GitHub subject-evidence root invocation ID",
            ),
        ] {
            if value.is_nil() {
                return Err(GithubSubjectEvidenceValueError::NilUuid(field));
            }
        }
        let event_name = event_name.into();
        validate_evidence_text(&event_name, false)?;
        let git_ref = git_ref.into();
        validate_evidence_text(&git_ref, true)?;
        let provider_delivery_idempotency_key = provider_delivery_idempotency_key.into();
        validate_evidence_text(&provider_delivery_idempotency_key, false)?;
        validate_timestamp(admitted_at)?;
        if admission_claim.claim().delivery_id() != delivery_id
            || !admission_claim.authorizes(admitted_at)
        {
            return Err(GithubSubjectEvidenceValueError::InvalidDeliveryClaim);
        }
        Ok(Self {
            tenant,
            repository_id,
            workflow_id,
            snapshot_id,
            run_id,
            root_invocation_id,
            delivery_id,
            provider_delivery_idempotency_key,
            admission_claim,
            head_sha,
            workflow_path,
            source_digest,
            event_name,
            event_digest,
            git_ref,
            plan_digest,
            logical_admission_digest,
            admitted_at,
        })
    }

    /// Derives signed subject evidence from one exact logical admission command.
    ///
    /// # Errors
    ///
    /// Rejects a generic 32-byte head because GitHub Check evidence is an exact
    /// nonzero 20-byte SHA-1 value, plus all errors documented by [`Self::new`].
    pub fn from_logical_admission(
        admission_claim: AuthenticatedGithubDeliveryClaim,
        command: &AdmitLogicalWorkflowRun,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        validate_github_logical_admission(command)?;
        let head_sha = GithubCheckHeadSha::try_from_slice(command.head_sha())
            .map_err(|_| GithubSubjectEvidenceValueError::InvalidHeadSha)?;
        let workflow_path = GithubCheckSubjectKey::new(command.workflow_path())
            .map_err(|_| GithubSubjectEvidenceValueError::InvalidEvidenceText)?;
        Self::new(
            command.tenant().clone(),
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            command.root_invocation_id(),
            admission_claim.claim().delivery_id(),
            command.idempotency().key(),
            admission_claim,
            head_sha,
            workflow_path,
            command.source().digest(),
            command.event_name(),
            command.event().digest(),
            command.git_ref(),
            command.plan().digest(),
            command.request_digest(),
            command.admitted_at(),
        )
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    /// Returns the exact internal repository.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    /// Returns the exact workflow definition.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }
    /// Returns the exact immutable workflow snapshot.
    #[must_use]
    pub const fn snapshot_id(&self) -> WorkflowSnapshotId {
        self.snapshot_id
    }
    /// Returns the exact admitted workflow run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }
    /// Returns the exact root logical invocation.
    #[must_use]
    pub const fn root_invocation_id(&self) -> LogicalWorkflowInvocationId {
        self.root_invocation_id
    }
    /// Returns the manifest-pinned signed provider delivery.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.delivery_id
    }
    /// Returns the exact namespaced `ProviderDelivery` admission key.
    #[must_use]
    pub fn provider_delivery_idempotency_key(&self) -> &str {
        &self.provider_delivery_idempotency_key
    }
    /// Returns the immutable claim that authorized initial run creation.
    #[must_use]
    pub const fn admission_claim(&self) -> AuthenticatedGithubDeliveryClaim {
        self.admission_claim
    }
    /// Returns the exact GitHub source revision and Check head.
    #[must_use]
    pub const fn head_sha(&self) -> GithubCheckHeadSha {
        self.head_sha
    }
    /// Returns the exact admitted workflow path.
    #[must_use]
    pub const fn workflow_path(&self) -> &GithubCheckSubjectKey {
        &self.workflow_path
    }
    /// Returns the immutable workflow-source content digest.
    #[must_use]
    pub const fn source_digest(&self) -> Sha256Digest {
        self.source_digest
    }
    /// Returns the exact provider event selector.
    #[must_use]
    pub fn event_name(&self) -> &str {
        &self.event_name
    }
    /// Returns the immutable provider-event object digest.
    #[must_use]
    pub const fn event_digest(&self) -> Sha256Digest {
        self.event_digest
    }
    /// Returns the exact full source ref.
    #[must_use]
    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }
    /// Returns the fixed logical workflow schema.
    #[must_use]
    pub const fn plan_schema(&self) -> u16 {
        WORKFLOW_PLAN_SCHEMA
    }
    /// Returns the immutable logical workflow digest.
    #[must_use]
    pub const fn plan_digest(&self) -> Sha256Digest {
        self.plan_digest
    }
    /// Returns the exact logical-admission aggregate digest.
    #[must_use]
    pub const fn logical_admission_digest(&self) -> Sha256Digest {
        self.logical_admission_digest
    }
    /// Returns the trusted admission/run-creation time.
    #[must_use]
    pub const fn admitted_at(&self) -> UnixMillis {
        self.admitted_at
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) fn matches_logical_admission(
        &self,
        delivery_id: ProviderDeliveryId,
        durable_admitted_at: UnixMillis,
        command: &AdmitLogicalWorkflowRun,
    ) -> bool {
        self.tenant == *command.tenant()
            && self.repository_id == command.repository().id()
            && self.workflow_id == command.workflow_id()
            && self.snapshot_id == command.snapshot_id()
            && self.run_id == command.run_id()
            && self.root_invocation_id == command.root_invocation_id()
            && self.delivery_id == delivery_id
            && self.provider_delivery_idempotency_key == command.idempotency().key()
            && self.head_sha.as_bytes().as_slice() == command.head_sha()
            && self.workflow_path.as_str() == command.workflow_path()
            && self.source_digest == command.source().digest()
            && self.event_name == command.event_name()
            && self.event_digest == command.event().digest()
            && self.git_ref == command.git_ref()
            && self.plan_digest == command.plan().digest()
            && self.logical_admission_digest == command.request_digest()
            && self.admitted_at == durable_admitted_at
    }
}

impl fmt::Debug for RecordGithubWorkflowRunSubjectEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecordGithubWorkflowRunSubjectEvidence([REDACTED])")
    }
}

/// Exact current claim authorization for replay of immutable GitHub run evidence.
#[derive(Clone)]
pub struct ValidateGithubWorkflowRunSubjectEvidenceReplay {
    current_claim: AuthenticatedGithubDeliveryClaim,
    observed_at: UnixMillis,
    durable_admitted_at: UnixMillis,
    #[cfg(feature = "adapter-spi")]
    command: AdmitLogicalWorkflowRun,
}

impl ValidateGithubWorkflowRunSubjectEvidenceReplay {
    /// Constructs a current-claim authorization for one exact logical replay.
    ///
    /// The current claim may be a later attempt/fence after crash recovery; it
    /// never replaces the immutable initial claim retained by the run receipt.
    ///
    /// # Errors
    ///
    /// Rejects local/manual admission, non-GitHub source shapes, or an
    /// observation outside the supplied claim's exclusive horizon.
    pub fn from_logical_admission(
        current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
        durable_admitted_at: UnixMillis,
        command: &AdmitLogicalWorkflowRun,
    ) -> Result<Self, GithubSubjectEvidenceValueError> {
        validate_github_logical_admission(command)?;
        GithubCheckHeadSha::try_from_slice(command.head_sha())
            .map_err(|_| GithubSubjectEvidenceValueError::InvalidHeadSha)?;
        GithubCheckSubjectKey::new(command.workflow_path())
            .map_err(|_| GithubSubjectEvidenceValueError::InvalidEvidenceText)?;
        validate_timestamp(observed_at)?;
        validate_timestamp(durable_admitted_at)?;
        if !current_claim.authorizes(observed_at) {
            return Err(GithubSubjectEvidenceValueError::InvalidDeliveryClaim);
        }
        Ok(Self {
            current_claim,
            observed_at,
            durable_admitted_at,
            #[cfg(feature = "adapter-spi")]
            command: command.clone(),
        })
    }

    /// Returns the exact record-locked claim that must authorize this replay.
    #[must_use]
    pub const fn current_claim(&self) -> AuthenticatedGithubDeliveryClaim {
        self.current_claim
    }

    /// Returns the trusted current observation, strictly before claim expiry.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the immutable original run-creation time loaded on replay.
    #[must_use]
    pub const fn durable_admitted_at(&self) -> UnixMillis {
        self.durable_admitted_at
    }

    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn command(&self) -> &AdmitLogicalWorkflowRun {
        &self.command
    }
}

impl fmt::Debug for ValidateGithubWorkflowRunSubjectEvidenceReplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidateGithubWorkflowRunSubjectEvidenceReplay([REDACTED])")
    }
}

/// Immutable per-run signed-owner evidence and its canonical digest.
#[derive(Clone, Eq, PartialEq)]
pub struct GithubWorkflowRunSubjectEvidence {
    request: RecordGithubWorkflowRunSubjectEvidence,
    check_subject_id: GithubCheckSubjectId,
    subject_evidence_sha256: Sha256Digest,
}

impl GithubWorkflowRunSubjectEvidence {
    /// Rehydrates one immutable run receipt from checked durable parts.
    #[must_use]
    pub fn from_durable_parts(
        request: RecordGithubWorkflowRunSubjectEvidence,
        check_subject_id: GithubCheckSubjectId,
        subject_evidence_sha256: Sha256Digest,
    ) -> Self {
        Self {
            request,
            check_subject_id,
            subject_evidence_sha256,
        }
    }

    /// Returns all exact logical-admission evidence.
    #[must_use]
    pub const fn request(&self) -> &RecordGithubWorkflowRunSubjectEvidence {
        &self.request
    }
    /// Returns the authenticated tenant scope retained by the receipt.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        self.request.tenant()
    }
    /// Returns the exact internal repository.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.request.repository_id()
    }
    /// Returns the exact admitted workflow run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.request.run_id()
    }
    /// Returns the exact signed provider delivery.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.request.delivery_id()
    }
    /// Returns the immutable provider claim that authorized initial admission.
    #[must_use]
    pub const fn admission_claim(&self) -> AuthenticatedGithubDeliveryClaim {
        self.request.admission_claim()
    }
    /// Returns the exact Check subject atomically linked to the run.
    #[must_use]
    pub const fn check_subject_id(&self) -> GithubCheckSubjectId {
        self.check_subject_id
    }
    /// Returns the canonical digest of all immutable signed source evidence.
    #[must_use]
    pub const fn subject_evidence_sha256(&self) -> Sha256Digest {
        self.subject_evidence_sha256
    }
    /// Returns the trusted admission time, equal to run creation time.
    #[must_use]
    pub const fn admitted_at(&self) -> UnixMillis {
        self.request.admitted_at()
    }
}

impl fmt::Debug for GithubWorkflowRunSubjectEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubWorkflowRunSubjectEvidence([REDACTED])")
    }
}

/// Value-construction failures at the signed-owner evidence boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubSubjectEvidenceValueError {
    /// The combined acceptance API is GitHub-only.
    #[error("manifest-pinned delivery acceptance requires the GitHub provider")]
    NotGithub,
    /// Signed and configured stable owner identities disagree.
    #[error("signed GitHub repository owner does not match configured authority")]
    RepositoryOwnerMismatch,
    /// Authenticated event/ref coordinates are not canonical.
    #[error("authenticated GitHub event evidence is invalid")]
    InvalidAuthenticatedEvent,
    /// A durable UUID uses the nil sentinel.
    #[error("{0} must not use the nil UUID sentinel")]
    NilUuid(&'static str),
    /// A durable timestamp predates the Unix epoch.
    #[error("GitHub subject-evidence time must not predate the Unix epoch")]
    NegativeTimestamp,
    /// A server-service selector does not match the pinned manifest.
    #[error("GitHub subject-evidence authority selector does not match the provider manifest")]
    AuthorityPinMismatch,
    /// The authenticated HMAC key evidence differs from the pinned manifest.
    #[error("authenticated GitHub webhook verifier does not match the provider manifest")]
    WebhookVerifierPinMismatch,
    /// Generic admission used a non-GitHub head shape.
    #[error("GitHub subject evidence requires an exact nonzero 20-byte head SHA")]
    InvalidHeadSha,
    /// Provider-only admission was invoked with local/manual authority.
    #[error("GitHub subject evidence requires provider-delivery admission authority")]
    InvalidAdmissionAuthority,
    /// Delivery claim evidence is malformed, mismatched, or outside its horizon.
    #[error("GitHub subject evidence requires an exact live provider-delivery claim")]
    InvalidDeliveryClaim,
    /// Event/ref/path evidence is empty, oversized, or noncanonical.
    #[error("GitHub subject-evidence text is not canonical")]
    InvalidEvidenceText,
}

/// Portable persistence failures with value-free diagnostics.
#[derive(Debug, Error)]
pub enum GithubSubjectEvidenceStoreError {
    /// Backend I/O or transaction failure.
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    /// No exact current manifest or repository authority accepts the delivery.
    #[error("GitHub delivery authority is unavailable or does not match")]
    AuthorityRejected,
    /// A replay key or run identity already names different immutable evidence.
    #[error("GitHub subject evidence conflicts with immutable durable state")]
    ReplayConflict,
    /// The exact immutable evidence receipt does not exist.
    #[error("GitHub subject evidence was not found")]
    NotFound,
    /// Durable records violate the current-only signed-owner contract.
    #[error("durable GitHub subject evidence is corrupt")]
    CorruptData,
}

impl GithubSubjectEvidenceStoreError {
    /// Wraps a backend error behind the repository's sanitized error boundary.
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }
}

/// Atomic GitHub ingress and immutable per-run subject-evidence repository.
#[async_trait]
pub trait GithubSubjectEvidenceRepository: Send + Sync {
    /// Atomically accepts a manifest/authority-pinned delivery and queued Check.
    async fn accept_manifest_pinned_github_delivery(
        &self,
        request: AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError>;

    /// Loads exact immutable worker/admission evidence for one inbox record.
    async fn load_manifest_pinned_github_delivery_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError>;

    /// Loads one exact tenant/repository/run-scoped evidence receipt.
    async fn load_github_workflow_run_subject_evidence(
        &self,
        tenant: &TenantScope,
        repository_id: RepositoryId,
        run_id: RunId,
    ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError>;
}

fn selector_matches_manifest(
    selector: &GithubServerServiceAuthoritySelector,
    manifest: &GithubProviderManifest,
) -> bool {
    selector.tenant() == manifest.tenant()
        && selector.app_configuration_revision() == manifest.app_configuration_revision()
        && selector.policy_revision() == manifest.policy_revision()
}

fn validate_github_logical_admission(
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), GithubSubjectEvidenceValueError> {
    if !matches!(
        command.idempotency(),
        WorkflowAdmissionIdempotency::ProviderDelivery(_)
    ) || command.repository().provider() != "github"
    {
        return Err(GithubSubjectEvidenceValueError::InvalidAdmissionAuthority);
    }
    Ok(())
}

fn validate_timestamp(value: UnixMillis) -> Result<(), GithubSubjectEvidenceValueError> {
    if value.get() < 0 {
        return Err(GithubSubjectEvidenceValueError::NegativeTimestamp);
    }
    Ok(())
}

fn validate_evidence_text(
    value: &str,
    require_git_ref: bool,
) -> Result<(), GithubSubjectEvidenceValueError> {
    if value.is_empty()
        || value.len() > MAX_EVIDENCE_TEXT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
        || require_git_ref && value.strip_prefix("refs/").is_none_or(str::is_empty)
    {
        return Err(GithubSubjectEvidenceValueError::InvalidEvidenceText);
    }
    Ok(())
}
