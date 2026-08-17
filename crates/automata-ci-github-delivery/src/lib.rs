//! Verified GitHub event acceptance into Automata's durable provider inbox.
//!
//! This boundary authenticates and normalizes an exact webhook request before
//! it performs any write. It then persists the authenticated raw JSON in the
//! immutable blob store, seals a bounded facts-only event envelope against that
//! object, and only after the blob write completes records both identities in
//! the provider-delivery inbox. Provider I/O, object reads, workflow discovery,
//! and compilation belong to a later worker and never run in the inbox
//! acceptance call.
//!
//! # Request digest
//!
//! The request digest is SHA-256 over the domain
//! `automata.github-delivery-ingress.event-request\0`, an unsigned big-endian
//! 16-bit field count, and thirteen ordered fields. Each field is encoded as an
//! unsigned big-endian 16-bit label length and label bytes followed by an
//! unsigned big-endian 64-bit value length and value bytes. In order, those
//! fields are the exact singleton signature, event, and delivery headers; the
//! exact authenticated body; and the tenant, provider, connection UUID,
//! installation ID, repository and repository-owner IDs, authenticated
//! repository visibility, canonical owner/name, and delivery ID from the
//! complete [`ProviderDeliveryIdentity`]. Numeric provider IDs are encoded as unsigned
//! big-endian 64-bit values and the UUID uses its canonical 16 bytes. This
//! encoding makes header or routing drift a durable replay conflict instead
//! of silently aliasing changed evidence.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod changed_files;
mod checks_presentation;
mod checks_publisher;
mod processor;
mod schedule;
mod service;
mod worker;

pub use checks_publisher::{
    GithubChecksCredentialProvider, GithubChecksCredentialProviderError,
    GithubChecksCredentialRequest, GithubChecksCredentialValueError, GithubChecksPublisher,
    GithubChecksPublisherConfig, GithubChecksPublisherConfigurationError,
    GithubChecksPublisherError, GithubChecksPublisherOutcome, GithubChecksServerServiceCredential,
};

pub use changed_files::GithubRestPushChangedFilesProvider;

pub use processor::{
    GithubChangedFileSelection, GithubChangedFilesDisposition,
    GithubDeliveryWorkflowAdmissionProcessor, GithubPullRequestChangedFilesAuthority,
    GithubPullRequestChangedFilesRequest, GithubPushChangedFilesAuthority,
    GithubPushChangedFilesProvider, GithubPushChangedFilesRequest,
};

pub use service::{
    GithubDeliveryPrivateRepositoryAction, GithubDeliveryService, GithubDeliveryServiceConfig,
    GithubDeliveryServiceConfigurationError, GithubDeliveryServiceError,
    GithubDeliveryServiceOutcome, GithubDeliverySourceCredential,
    GithubDeliverySourceCredentialBinding, GithubDeliverySourceCredentialProvider,
    GithubDeliverySourceCredentialProviderError, GithubDeliverySourceCredentialRequest,
    GithubDeliverySourceCredentialValueError, GithubServerServiceCredentialRelease,
};

pub use schedule::{
    GithubScheduleClock, GithubSchedulePrivateSourceAuthorities, GithubScheduleService,
    GithubScheduleServiceConfig, GithubScheduleServiceConfigurationError,
    GithubScheduleServiceError, GithubScheduleServicePass, GithubScheduleSourceCredential,
    GithubScheduleSourceCredentialProvider, GithubScheduleSourceCredentialProviderError,
    GithubScheduleSourceCredentialRequest, GithubScheduleSourceCredentialValueError,
};

pub use worker::{
    GithubDeliveryClaimSnapshot, GithubDeliverySourceAuthority, GithubDeliveryWorker,
    GithubDeliveryWorkerConfig, GithubDeliveryWorkerConfigurationError, GithubDeliveryWorkerError,
    GithubDeliveryWorkerOutcome, GithubDeliveryWorkerPrerequisite, GithubDeliveryWorkflowProcessor,
    GithubDeliveryWorkflowProcessorCompletion, GithubDeliveryWorkflowProcessorError,
    GithubDeliveryWorkflowRequest,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use automata_ci_blob::{BlobKey, BlobPayload, BlobStoreErrorKind, ImmutableBlobStore, MediaType};
use automata_ci_core::{Sha256Digest, UnixMillis};
#[cfg(test)]
use automata_ci_github::VerifiedGithubPush;
use automata_ci_github::{
    GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE, GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX, GithubCheckRunAction,
    GithubRepositoryVisibility, GithubSealedEventEnvelopeV1, GithubWebhookError,
    GithubWebhookVerifier, VerifiedGithubWebhook, X_GITHUB_DELIVERY, X_GITHUB_EVENT,
    X_HUB_SIGNATURE_256,
};
use automata_ci_provider::ProviderConnectionId;
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptManifestPinnedGithubRepositoryDispatch,
    AcceptProviderDelivery, AdmissionObject, GithubAuthenticatedEvent,
    GithubAuthenticatedEventKind, GithubCheckAppId, GithubCheckHeadSha, GithubCheckRerunAction,
    GithubCheckRerunRepository, GithubCheckRerunRequest, GithubCheckRerunStoreError,
    GithubCheckRerunTarget, GithubCheckRunId, GithubCheckSuiteId,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryDispatchEvidenceRepository,
    GithubServerServiceRevision, GithubSubjectEvidenceRepository, GithubSubjectEvidenceStoreError,
    ManifestPinnedGithubDeliveryReceipt, ObjectKey, PendingGithubRepositoryDispatchReceipt,
    ProviderDeliveryEventEnvelope, ProviderDeliveryIdentity, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, StoreError, TenantScope,
};
use bytes::Bytes;
use http::HeaderMap;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Media type for a generic authenticated raw GitHub event.
pub const GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE: &str =
    automata_ci_github::GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE;
/// Maximum exact repository connections accepted by one webhook verifier.
pub const MAX_GITHUB_DELIVERY_CONNECTIONS: usize = 256;

const PROVIDER: &str = "github";
const EVENT_REQUEST_DIGEST_DOMAIN: &[u8] = b"automata.github-delivery-ingress.event-request\0";
const REQUEST_DIGEST_FIELD_COUNT: u16 = 13;
const MAX_REPOSITORY_COMPONENT_BYTES: usize = 100;

/// One configured GitHub delivery connection and its exact repository binding.
///
/// Stable numeric provider identities remain authoritative. The configured
/// owner and repository name are authenticated display/routing evidence and
/// must agree exactly with the normalized push payload.
pub struct GithubDeliveryConnection {
    tenant: TenantScope,
    connection_id: ProviderConnectionId,
    installation_id: ProviderInstallationId,
    repository_id: ProviderRepositoryId,
    repository_owner_id: ProviderRepositoryOwnerId,
    repository_visibility: ProviderRepositoryVisibility,
    repository_owner: Box<str>,
    repository_name: Box<str>,
    default_branch_ref: Option<Box<str>>,
}

impl GithubDeliveryConnection {
    /// Constructs one exact configured connection.
    ///
    /// # Errors
    ///
    /// Rejects an owner or repository name outside the same canonical shape
    /// accepted from GitHub push payloads.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        connection_id: ProviderConnectionId,
        installation_id: ProviderInstallationId,
        repository_id: ProviderRepositoryId,
        repository_owner_id: ProviderRepositoryOwnerId,
        repository_visibility: ProviderRepositoryVisibility,
        repository_owner: impl Into<Box<str>>,
        repository_name: impl Into<Box<str>>,
    ) -> Result<Self, GithubDeliveryConfigurationError> {
        let repository_owner = repository_owner.into();
        let repository_name = repository_name.into();
        validate_repository_component(&repository_owner)?;
        validate_repository_component(&repository_name)?;
        if has_ascii_case_insensitive_suffix(&repository_name, ".git") {
            return Err(GithubDeliveryConfigurationError::InvalidRepositoryIdentity);
        }
        Ok(Self {
            tenant,
            connection_id,
            installation_id,
            repository_id,
            repository_owner_id,
            repository_visibility,
            repository_owner,
            repository_name,
            default_branch_ref: None,
        })
    }

    /// Binds the configured full default-branch ref used by custom dispatches.
    ///
    /// # Errors
    ///
    /// Rejects a non-branch, control-bearing, empty, or excessive full ref.
    pub fn with_default_branch_ref(
        mut self,
        default_branch_ref: impl Into<Box<str>>,
    ) -> Result<Self, GithubDeliveryConfigurationError> {
        let default_branch_ref = default_branch_ref.into();
        if !valid_default_branch_ref(&default_branch_ref) {
            return Err(GithubDeliveryConfigurationError::InvalidDefaultBranchRef);
        }
        self.default_branch_ref = Some(default_branch_ref);
        Ok(self)
    }

    /// Returns the authenticated tenant scope bound to this connection.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the server-owned connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the expected GitHub App installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.installation_id
    }

    /// Returns the expected stable GitHub repository identity.
    #[must_use]
    pub const fn repository_id(&self) -> ProviderRepositoryId {
        self.repository_id
    }

    /// Returns the expected stable GitHub repository-owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the expected authenticated repository visibility.
    #[must_use]
    pub const fn repository_visibility(&self) -> ProviderRepositoryVisibility {
        self.repository_visibility
    }

    /// Returns the configured canonical repository owner.
    #[must_use]
    pub fn repository_owner(&self) -> &str {
        &self.repository_owner
    }

    /// Returns the configured canonical repository name.
    #[must_use]
    pub fn repository_name(&self) -> &str {
        &self.repository_name
    }

    /// Returns the configured full default-branch ref when dispatch is enabled.
    #[must_use]
    pub fn default_branch_ref(&self) -> Option<&str> {
        self.default_branch_ref.as_deref()
    }

    fn matches_selected_event(
        &self,
        event: &VerifiedGithubWebhook,
        signed_repository_owner_id: ProviderRepositoryOwnerId,
    ) -> bool {
        self.matches_repository(
            event.installation_id().get(),
            event.repository(),
            signed_repository_owner_id,
        ) && match event {
            VerifiedGithubWebhook::RepositoryDispatch(dispatch) => {
                self.default_branch_ref() == Some(dispatch.git_ref())
            }
            _ => true,
        }
    }

    fn matches_repository(
        &self,
        installation_id: u64,
        repository: &automata_ci_github::GithubWebhookRepository,
        signed_repository_owner_id: ProviderRepositoryOwnerId,
    ) -> bool {
        installation_id == self.installation_id.get()
            && repository.id().get() == self.repository_id.get()
            && signed_repository_owner_id == self.repository_owner_id
            && provider_visibility(repository.visibility()) == self.repository_visibility
            && repository.owner() == self.repository_owner()
            && repository.name() == self.repository_name()
    }

    const fn selector(&self) -> (ProviderInstallationId, ProviderRepositoryId) {
        (self.installation_id, self.repository_id)
    }

    fn repository_identity(&self) -> String {
        let mut identity =
            String::with_capacity(self.repository_owner.len() + 1 + self.repository_name.len());
        identity.push_str(&self.repository_owner);
        identity.push('/');
        identity.push_str(&self.repository_name);
        identity
    }
}

impl fmt::Debug for GithubDeliveryConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryConnection")
            .field("tenant", &"[redacted]")
            .field("connection_id", &self.connection_id)
            .field("installation_id", &self.installation_id)
            .field("repository_id", &self.repository_id)
            .field("repository_owner_id", &self.repository_owner_id)
            .field("repository_visibility", &self.repository_visibility)
            .field("repository_owner", &"[redacted]")
            .field("repository_name", &"[redacted]")
            .field("default_branch_ref", &"[redacted]")
            .finish()
    }
}

/// Sanitized invalid connection configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubDeliveryConfigurationError {
    /// The verifier could not produce valid public key-revision evidence.
    #[error("the GitHub webhook verifier evidence is invalid")]
    InvalidVerifierEvidence,
    /// A webhook verifier was configured without any repository connections.
    #[error("the GitHub delivery connection registry is empty")]
    EmptyConnectionRegistry,
    /// A webhook verifier was configured with more than the closed connection limit.
    #[error("the GitHub delivery connection registry exceeds its limit")]
    TooManyConnections,
    /// The configured owner or repository name is not canonical.
    #[error("the configured GitHub repository identity is invalid")]
    InvalidRepositoryIdentity,
    /// The configured default branch is not a bounded full branch ref.
    #[error("the configured GitHub default-branch ref is invalid")]
    InvalidDefaultBranchRef,
    /// More than one entry used the same server-owned connection identity.
    #[error("the GitHub delivery connection identity is duplicated")]
    DuplicateConnectionId,
    /// More than one entry used the same numeric installation/repository selector.
    #[error("the GitHub delivery numeric repository selector is duplicated")]
    DuplicateRepositorySelector,
    /// More than one entry used the same stable numeric repository identity.
    #[error("the GitHub delivery numeric repository identity is duplicated")]
    DuplicateRepositoryId,
    /// More than one entry used the same canonical owner/repository identity.
    #[error("the GitHub delivery repository identity is duplicated")]
    DuplicateRepositoryIdentity,
}

/// Trusted wall clock shared by delivery claim, renewal, and reclaim authority.
///
/// Values must be non-negative and nondecreasing within one service process,
/// every replica must use a coherently synchronized authority, and `now` must
/// return promptly without blocking the asynchronous supervisor. Renewal
/// periodically pairs this clock with a monotonic deadline and only narrows
/// custody. A deployment that permits an arbitrary forward wall step to cross
/// predecessor expiry between the final guard sample and the repository's
/// row-lock/commit point must enforce current time inside that repository
/// transaction; application-side polling cannot undo an already committed
/// successor.
pub trait GithubDeliveryClock: fmt::Debug + Send + Sync {
    /// Returns the trusted current Unix time in milliseconds.
    fn now(&self) -> UnixMillis;
}

/// Successful durable acceptance evidence.
///
/// The provider inbox owns the authoritative receipt. This narrow result gives
/// an HTTP boundary enough stable, credential-free evidence to observe the
/// accepted request without exposing the authenticated body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedGithubDelivery {
    receipt: ManifestPinnedGithubDeliveryReceipt,
    request_digest: Sha256Digest,
    raw_event: AdmissionObject,
}

impl AcceptedGithubDelivery {
    /// Returns the authoritative durable inbox receipt.
    #[must_use]
    pub const fn receipt(&self) -> &ManifestPinnedGithubDeliveryReceipt {
        &self.receipt
    }

    /// Returns the canonical digest of all verified request evidence.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the immutable descriptor of the authenticated raw JSON.
    #[must_use]
    pub const fn raw_event(&self) -> &AdmissionObject {
        &self.raw_event
    }
}

/// Durable pre-resolution receipt for one authenticated custom dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedGithubRepositoryDispatch {
    receipt: PendingGithubRepositoryDispatchReceipt,
    request_digest: Sha256Digest,
    raw_event: AdmissionObject,
}

impl AcceptedGithubRepositoryDispatch {
    /// Returns the exact manifest and least-authority pins accepted durably.
    #[must_use]
    pub const fn receipt(&self) -> &PendingGithubRepositoryDispatchReceipt {
        &self.receipt
    }

    /// Returns the canonical digest of all verified request evidence.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the immutable descriptor of the authenticated raw JSON.
    #[must_use]
    pub const fn raw_event(&self) -> &AdmissionObject {
        &self.raw_event
    }
}

/// Durable repositories used by authenticated GitHub webhook ingress.
#[derive(Clone)]
pub struct GithubDeliveryRepositories {
    deliveries: Arc<dyn GithubSubjectEvidenceRepository>,
    repository_dispatches: Option<Arc<dyn GithubRepositoryDispatchEvidenceRepository>>,
    check_reruns: Option<Arc<dyn GithubCheckRerunRepository>>,
}

impl GithubDeliveryRepositories {
    /// Creates the required webhook-evidence repository set.
    #[must_use]
    pub fn new(deliveries: Arc<dyn GithubSubjectEvidenceRepository>) -> Self {
        Self {
            deliveries,
            repository_dispatches: None,
            check_reruns: None,
        }
    }

    /// Adds durable custom-dispatch pre-resolution.
    #[must_use]
    pub fn with_repository_dispatches(
        mut self,
        repository: Arc<dyn GithubRepositoryDispatchEvidenceRepository>,
    ) -> Self {
        self.repository_dispatches = Some(repository);
        self
    }

    /// Adds durable GitHub-native Check rerun admission.
    #[must_use]
    pub fn with_check_reruns(mut self, repository: Arc<dyn GithubCheckRerunRepository>) -> Self {
        self.check_reruns = Some(repository);
        self
    }
}

impl fmt::Debug for GithubDeliveryRepositories {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryRepositories")
            .field("deliveries", &"configured")
            .field(
                "repository_dispatches",
                &self.repository_dispatches.as_ref().map(|_| "configured"),
            )
            .field(
                "check_reruns",
                &self.check_reruns.as_ref().map(|_| "configured"),
            )
            .finish()
    }
}

/// Authenticated GitHub webhook ingress with one explicit repository set.
pub struct GithubDeliveryIngress {
    verifier: GithubWebhookVerifier,
    verifier_fingerprint: GithubProviderWebhookVerifierFingerprint,
    verifier_revision: GithubServerServiceRevision,
    connections: Arc<[GithubDeliveryConnection]>,
    connection_by_selector: BTreeMap<(ProviderInstallationId, ProviderRepositoryId), usize>,
    objects: Arc<dyn ImmutableBlobStore>,
    deliveries: Arc<dyn GithubSubjectEvidenceRepository>,
    repository_dispatches: Option<Arc<dyn GithubRepositoryDispatchEvidenceRepository>>,
    check_reruns: Option<Arc<dyn GithubCheckRerunRepository>>,
    clock: Arc<dyn GithubDeliveryClock>,
}

impl GithubDeliveryIngress {
    /// Constructs one bounded verify-once ingress registry.
    ///
    /// Connections are retained in numeric selector order. One shared verifier
    /// authenticates the request before its signed installation/repository pair
    /// selects exactly one entry.
    ///
    /// # Errors
    ///
    /// Rejects an empty or excessive registry and any duplicate connection,
    /// numeric selector, stable repository ID, or canonical repository identity.
    pub fn new(
        verifier: GithubWebhookVerifier,
        verifier_revision: GithubServerServiceRevision,
        mut connections: Vec<GithubDeliveryConnection>,
        objects: Arc<dyn ImmutableBlobStore>,
        repositories: GithubDeliveryRepositories,
        clock: Arc<dyn GithubDeliveryClock>,
    ) -> Result<Self, GithubDeliveryConfigurationError> {
        if connections.is_empty() {
            return Err(GithubDeliveryConfigurationError::EmptyConnectionRegistry);
        }
        if connections.len() > MAX_GITHUB_DELIVERY_CONNECTIONS {
            return Err(GithubDeliveryConfigurationError::TooManyConnections);
        }
        connections.sort_unstable_by_key(GithubDeliveryConnection::selector);

        let mut connection_ids = BTreeSet::new();
        for connection in &connections {
            if !connection_ids.insert(connection.connection_id) {
                return Err(GithubDeliveryConfigurationError::DuplicateConnectionId);
            }
        }

        let mut connection_by_selector = BTreeMap::new();
        for (index, connection) in connections.iter().enumerate() {
            if connection_by_selector
                .insert(connection.selector(), index)
                .is_some()
            {
                return Err(GithubDeliveryConfigurationError::DuplicateRepositorySelector);
            }
        }

        let mut repository_ids = BTreeSet::new();
        for connection in &connections {
            if !repository_ids.insert(connection.repository_id) {
                return Err(GithubDeliveryConfigurationError::DuplicateRepositoryId);
            }
        }

        let mut repository_identities = BTreeSet::new();
        for connection in &connections {
            if !repository_identities.insert(connection.repository_identity()) {
                return Err(GithubDeliveryConfigurationError::DuplicateRepositoryIdentity);
            }
        }

        let verifier_fingerprint = GithubProviderWebhookVerifierFingerprint::from_sha256(
            Sha256Digest::from_bytes(*verifier.fingerprint().as_bytes()),
        )
        .map_err(|_| GithubDeliveryConfigurationError::InvalidVerifierEvidence)?;

        Ok(Self {
            verifier,
            verifier_fingerprint,
            verifier_revision,
            connections: connections.into(),
            connection_by_selector,
            objects,
            deliveries: repositories.deliveries,
            repository_dispatches: repositories.repository_dispatches,
            check_reruns: repositories.check_reruns,
            clock,
        })
    }

    /// Returns configured connections in stable numeric selector order.
    #[must_use]
    pub fn connections(&self) -> &[GithubDeliveryConnection] {
        &self.connections
    }

    /// Authenticates and durably accepts one supported GitHub event.
    ///
    /// The canonical path stores explicit event and ref coordinates for push,
    /// pull-request, and merge-group evidence.
    ///
    /// # Errors
    ///
    /// Returns the same sanitized verification, authority, object, time, and
    /// inbox failures as [`Self::accept`].
    pub async fn accept(
        &self,
        headers: &HeaderMap,
        raw_body: Bytes,
    ) -> Result<AcceptedGithubDelivery, GithubDeliveryIngressError> {
        let selected = self.authenticate_and_select_event(headers, raw_body)?;
        if matches!(
            &selected.event,
            VerifiedGithubWebhook::RepositoryDispatch(_)
                | VerifiedGithubWebhook::CheckRun(_)
                | VerifiedGithubWebhook::CheckSuite(_)
        ) {
            return Err(GithubDeliveryIngressError::InvariantViolation);
        }
        let connection = self.selected_connection(selected.connection_index)?;
        let event_coordinates = authenticated_event_coordinates(&selected.event)?;
        let prepared = self
            .persist_authenticated_event(headers, &selected, connection)
            .await?;
        let request = AcceptManifestPinnedGithubDelivery::new(
            prepared.delivery,
            selected.signed_repository_owner_id,
            connection.repository_owner_id,
            event_coordinates.event,
            event_coordinates.head_sha,
            self.verifier_fingerprint,
            self.verifier_revision,
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let receipt = self
            .deliveries
            .accept_manifest_pinned_github_delivery(request)
            .await
            .map_err(|error| GithubDeliveryIngressError::from_subject_store(&error))?;
        Ok(AcceptedGithubDelivery {
            receipt,
            request_digest: prepared.request_digest,
            raw_event: prepared.raw_event,
        })
    }

    /// Authenticates and durably pins one custom repository dispatch.
    ///
    /// No mutable branch lookup occurs at ingress. The accepted row carries
    /// the exact default-branch ref and least-authority selector; a claimed
    /// worker must bind an immutable commit before it can create a run.
    ///
    /// # Errors
    ///
    /// Fails closed when the dedicated store is absent, the event is not a
    /// repository dispatch, or its signed default branch differs from the
    /// connection's configured full ref. Other errors match [`Self::accept`].
    pub async fn accept_repository_dispatch(
        &self,
        headers: &HeaderMap,
        raw_body: Bytes,
    ) -> Result<AcceptedGithubRepositoryDispatch, GithubDeliveryIngressError> {
        let repository_dispatches = self
            .repository_dispatches
            .as_ref()
            .ok_or(GithubDeliveryIngressError::InvariantViolation)?;
        let selected = self.authenticate_and_select_event(headers, raw_body)?;
        let VerifiedGithubWebhook::RepositoryDispatch(dispatch) = &selected.event else {
            return Err(GithubDeliveryIngressError::InvariantViolation);
        };
        let connection = self.selected_connection(selected.connection_index)?;
        let event = GithubAuthenticatedEvent::new(
            GithubAuthenticatedEventKind::RepositoryDispatch,
            dispatch.git_ref(),
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let prepared = self
            .persist_authenticated_event(headers, &selected, connection)
            .await?;
        let request = AcceptManifestPinnedGithubRepositoryDispatch::new(
            prepared.delivery,
            selected.signed_repository_owner_id,
            connection.repository_owner_id,
            event,
            self.verifier_fingerprint,
            self.verifier_revision,
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let receipt = repository_dispatches
            .accept_manifest_pinned_github_repository_dispatch(request)
            .await
            .map_err(|error| GithubDeliveryIngressError::from_subject_store(&error))?;
        Ok(AcceptedGithubRepositoryDispatch {
            receipt,
            request_digest: prepared.request_digest,
            raw_event: prepared.raw_event,
        })
    }

    /// Authenticates and executes one GitHub-native Check rerun control.
    ///
    /// The exact Check/App/repository/commit identity is resolved by the store,
    /// which also maps the signed sender to current Automata authority before
    /// entering the normal idempotent workflow-rerun transaction.
    ///
    /// # Errors
    ///
    /// Fails closed for non-control events, mismatched Check identity, stale
    /// sender authority, an ineligible source, or an unavailable durable store.
    pub async fn accept_check_rerun(
        &self,
        headers: &HeaderMap,
        raw_body: Bytes,
    ) -> Result<usize, GithubDeliveryIngressError> {
        let check_reruns = self
            .check_reruns
            .as_ref()
            .ok_or(GithubDeliveryIngressError::InvariantViolation)?;
        let selected = self.authenticate_and_select_event(headers, raw_body)?;
        let connection = self.selected_connection(selected.connection_index)?;
        let (app_id, head_revision, sender_id, target) = match &selected.event {
            VerifiedGithubWebhook::CheckRun(check) => (
                check.app_id().get(),
                check.head_revision(),
                check.sender_id().get(),
                GithubCheckRerunTarget::Run {
                    run_id: GithubCheckRunId::new(check.run_id().get())
                        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?,
                    suite_id: GithubCheckSuiteId::new(check.suite_id().get())
                        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?,
                    external_id: check.external_id().to_owned(),
                    action: match check.action() {
                        GithubCheckRunAction::Rerequested => GithubCheckRerunAction::Rerequested,
                        GithubCheckRunAction::RerunAll => GithubCheckRerunAction::RerunAll,
                        GithubCheckRunAction::RerunFailed => GithubCheckRerunAction::RerunFailed,
                        GithubCheckRunAction::RerunJob => GithubCheckRerunAction::RerunJob,
                    },
                },
            ),
            VerifiedGithubWebhook::CheckSuite(check) => (
                check.app_id().get(),
                check.head_revision(),
                check.sender_id().get(),
                GithubCheckRerunTarget::Suite {
                    suite_id: GithubCheckSuiteId::new(check.suite_id().get())
                        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?,
                },
            ),
            _ => return Err(GithubDeliveryIngressError::InvariantViolation),
        };
        let request = GithubCheckRerunRequest::new(
            connection.tenant.clone(),
            connection.connection_id,
            connection.installation_id.get(),
            connection.repository_id.get(),
            GithubCheckAppId::new(app_id)
                .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?,
            github_check_head_sha(head_revision.as_str())?,
            sender_id,
            selected.event.delivery_id(),
            Sha256Digest::from_bytes(*selected.event.body_sha256().as_bytes()),
            target,
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let receipts = check_reruns
            .rerun_github_check(request)
            .await
            .map_err(|error| GithubDeliveryIngressError::from_check_rerun_store(&error))?;
        if receipts.is_empty() {
            return Err(GithubDeliveryIngressError::InvariantViolation);
        }
        Ok(receipts.len())
    }

    fn authenticate_and_select_event(
        &self,
        headers: &HeaderMap,
        raw_body: Bytes,
    ) -> Result<SelectedAuthenticatedGithubEvent, GithubDeliveryIngressError> {
        let event = self
            .verifier
            .authenticate(headers, raw_body)
            .and_then(automata_ci_github::AuthenticatedGithubWebhook::normalize)
            .map_err(GithubDeliveryIngressError::Webhook)?;
        let installation_id = ProviderInstallationId::new(event.installation_id().get())
            .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let repository_id = ProviderRepositoryId::new(event.repository().id().get())
            .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let signed_repository_owner_id =
            ProviderRepositoryOwnerId::new(event.repository().owner_id().get())
                .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let connection_index = self
            .connection_by_selector
            .get(&(installation_id, repository_id))
            .copied()
            .ok_or(GithubDeliveryIngressError::ConfiguredIdentityMismatch)?;
        let connection = self.selected_connection(connection_index)?;
        if !connection.matches_selected_event(&event, signed_repository_owner_id) {
            return Err(GithubDeliveryIngressError::ConfiguredIdentityMismatch);
        }
        Ok(SelectedAuthenticatedGithubEvent {
            event,
            connection_index,
            signed_repository_owner_id,
        })
    }

    fn selected_connection(
        &self,
        index: usize,
    ) -> Result<&GithubDeliveryConnection, GithubDeliveryIngressError> {
        self.connections
            .get(index)
            .ok_or(GithubDeliveryIngressError::InvariantViolation)
    }

    async fn persist_authenticated_event(
        &self,
        headers: &HeaderMap,
        selected: &SelectedAuthenticatedGithubEvent,
        connection: &GithubDeliveryConnection,
    ) -> Result<PreparedAuthenticatedGithubEvent, GithubDeliveryIngressError> {
        let accepted_at = self.clock.now();
        if accepted_at.get() < 0 {
            return Err(GithubDeliveryIngressError::InvalidTrustedTime);
        }
        let repository_visibility = provider_visibility(selected.event.repository().visibility());
        let repository = ProviderRepositoryCoordinates::new(
            connection.repository_id,
            repository_visibility,
            connection.repository_identity(),
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let identity = ProviderDeliveryIdentity::new(
            connection.tenant.clone(),
            PROVIDER,
            connection.connection_id,
            connection.installation_id,
            repository,
            selected.event.delivery_id(),
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let request_digest = canonical_event_request_digest(
            headers,
            &selected.event,
            &identity,
            selected.signed_repository_owner_id,
        )?;
        let body_digest = Sha256Digest::from_bytes(*selected.event.body_sha256().as_bytes());
        let object_key = format!("{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{body_digest}.json");
        let blob_key = BlobKey::new(object_key.clone())
            .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let media_type = MediaType::new(GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE)
            .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let payload =
            BlobPayload::from_bytes(blob_key, media_type, selected.event.raw_body().clone());
        if payload.descriptor().digest() != body_digest {
            return Err(GithubDeliveryIngressError::InvariantViolation);
        }
        let sealed_event =
            GithubSealedEventEnvelopeV1::seal(&selected.event, payload.descriptor().clone())
                .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let event_envelope = ProviderDeliveryEventEnvelope::new(
            sealed_event.schema(),
            sealed_event.registry_schema(),
            sealed_event.digest(),
            sealed_event.canonical_bytes().to_vec(),
            GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE,
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        self.objects
            .put_if_absent(payload)
            .await
            .map_err(|error| GithubDeliveryIngressError::RawObject { kind: error.kind() })?;
        let raw_event = AdmissionObject::new_event(
            body_digest,
            ObjectKey::new(object_key)
                .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?,
            u64::try_from(selected.event.raw_body().len())
                .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?,
            GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        let delivery = AcceptProviderDelivery::new(
            identity,
            request_digest,
            raw_event.clone(),
            event_envelope,
            accepted_at,
        )
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
        Ok(PreparedAuthenticatedGithubEvent {
            delivery,
            request_digest,
            raw_event,
        })
    }
}

struct SelectedAuthenticatedGithubEvent {
    event: VerifiedGithubWebhook,
    connection_index: usize,
    signed_repository_owner_id: ProviderRepositoryOwnerId,
}

struct PreparedAuthenticatedGithubEvent {
    delivery: AcceptProviderDelivery,
    request_digest: Sha256Digest,
    raw_event: AdmissionObject,
}

impl fmt::Debug for GithubDeliveryIngress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryIngress")
            .field("verifier", &self.verifier)
            .field("verifier_fingerprint", &self.verifier_fingerprint)
            .field("verifier_revision", &self.verifier_revision)
            .field("connection_count", &self.connections.len())
            .field("connections", &"[configured connections]")
            .field("selector_count", &self.connection_by_selector.len())
            .field("objects", &"[immutable blob store]")
            .field("deliveries", &"[provider delivery repository]")
            .field(
                "repository_dispatches",
                &self.repository_dispatches.as_ref().map(|_| "[configured]"),
            )
            .field(
                "check_reruns",
                &self.check_reruns.as_ref().map(|_| "[configured]"),
            )
            .field("clock", &self.clock)
            .finish()
    }
}

/// Sanitized delivery-ingress failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubDeliveryIngressError {
    /// Webhook authentication or normalization failed.
    #[error(transparent)]
    Webhook(GithubWebhookError),
    /// Authenticated provider identity disagreed with connection authority.
    #[error("the authenticated GitHub delivery does not match the configured connection")]
    ConfiguredIdentityMismatch,
    /// The injected trusted clock returned a pre-epoch timestamp.
    #[error("the trusted GitHub delivery clock returned an invalid timestamp")]
    InvalidTrustedTime,
    /// The authenticated raw object could not be durably persisted.
    #[error("authenticated GitHub delivery object persistence failed")]
    RawObject {
        /// Stable provider-neutral object-store failure class.
        kind: BlobStoreErrorKind,
    },
    /// The provider-delivery inbox backend was unavailable.
    #[error("the durable provider delivery inbox is unavailable")]
    InboxUnavailable,
    /// The same delivery identity was reused with changed immutable evidence.
    #[error("the GitHub delivery replay conflicts with durable evidence")]
    ReplayConflict,
    /// The current provider manifest did not authorize the authenticated delivery.
    #[error("the durable provider delivery inbox rejected the current authority")]
    InboxAuthorityRejected,
    /// Required durable provider-delivery evidence was unexpectedly absent.
    #[error("the durable provider delivery inbox evidence was not found")]
    InboxNotFound,
    /// Durable provider-delivery evidence failed invariant validation.
    #[error("the durable provider delivery inbox evidence was corrupt")]
    InboxCorrupt,
    /// The signed Check or current sender authority was rejected.
    #[error("the GitHub Check rerun was not authorized")]
    CheckRerunAuthorityRejected,
    /// The selected Check no longer represented an eligible terminal source.
    #[error("the GitHub Check rerun source is not eligible")]
    CheckRerunConflict,
    /// Trusted construction unexpectedly violated an internal invariant.
    #[error("trusted GitHub delivery construction violated an invariant")]
    InvariantViolation,
}

impl GithubDeliveryIngressError {
    fn from_subject_store(error: &GithubSubjectEvidenceStoreError) -> Self {
        match error {
            GithubSubjectEvidenceStoreError::Operation(_) => Self::InboxUnavailable,
            GithubSubjectEvidenceStoreError::ReplayConflict => Self::ReplayConflict,
            GithubSubjectEvidenceStoreError::AuthorityRejected => Self::InboxAuthorityRejected,
            GithubSubjectEvidenceStoreError::NotFound => Self::InboxNotFound,
            GithubSubjectEvidenceStoreError::CorruptData => Self::InboxCorrupt,
        }
    }

    fn from_check_rerun_store(error: &GithubCheckRerunStoreError) -> Self {
        match error {
            GithubCheckRerunStoreError::Store(StoreError::Operation(_)) => Self::InboxUnavailable,
            GithubCheckRerunStoreError::Store(_) => Self::InboxCorrupt,
            GithubCheckRerunStoreError::AuthorityRejected => Self::CheckRerunAuthorityRejected,
            GithubCheckRerunStoreError::Conflict => Self::CheckRerunConflict,
        }
    }
}

fn github_check_head_sha(value: &str) -> Result<GithubCheckHeadSha, GithubDeliveryIngressError> {
    if value.len() != 40 {
        return Err(GithubDeliveryIngressError::InvariantViolation);
    }
    let mut bytes = [0_u8; 20];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(GithubDeliveryIngressError::InvariantViolation)?;
        let low = hex_nibble(pair[1]).ok_or(GithubDeliveryIngressError::InvariantViolation)?;
        bytes[index] = (high << 4) | low;
    }
    GithubCheckHeadSha::new(bytes).map_err(|_| GithubDeliveryIngressError::InvariantViolation)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn canonical_event_request_digest(
    headers: &HeaderMap,
    event: &VerifiedGithubWebhook,
    identity: &ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
) -> Result<Sha256Digest, GithubDeliveryIngressError> {
    canonical_request_digest_with_domain(
        EVENT_REQUEST_DIGEST_DOMAIN,
        headers,
        event.raw_body(),
        identity,
        repository_owner_id,
    )
}

fn canonical_request_digest_with_domain(
    domain: &[u8],
    headers: &HeaderMap,
    raw_body: &[u8],
    identity: &ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
) -> Result<Sha256Digest, GithubDeliveryIngressError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(REQUEST_DIGEST_FIELD_COUNT.to_be_bytes());

    // Version 3 is an ordered sequence of labeled, length-prefixed byte
    // strings. Labels use a u16 big-endian byte length; values use a u64
    // big-endian byte length. Numeric identities use unsigned big-endian bytes
    // and UUIDs use their canonical 16-byte representation. The three headers
    // are exact singleton bytes validated by `GithubWebhookVerifier`.
    update_digest_field(
        &mut digest,
        b"header:x-hub-signature-256",
        verified_header(headers, X_HUB_SIGNATURE_256)?,
    );
    update_digest_field(
        &mut digest,
        b"header:x-github-event",
        verified_header(headers, X_GITHUB_EVENT)?,
    );
    update_digest_field(
        &mut digest,
        b"header:x-github-delivery",
        verified_header(headers, X_GITHUB_DELIVERY)?,
    );
    update_digest_field(&mut digest, b"body", raw_body);
    update_digest_field(
        &mut digest,
        b"identity:tenant",
        identity.tenant().as_str().as_bytes(),
    );
    update_digest_field(
        &mut digest,
        b"identity:provider",
        identity.provider().as_bytes(),
    );
    update_digest_field(
        &mut digest,
        b"identity:connection-id",
        identity.connection_id().as_uuid().as_bytes(),
    );
    update_digest_field(
        &mut digest,
        b"identity:installation-id",
        &identity.installation_id().get().to_be_bytes(),
    );
    update_digest_field(
        &mut digest,
        b"identity:repository-id",
        &identity.repository_id().get().to_be_bytes(),
    );
    update_digest_field(
        &mut digest,
        b"identity:repository-owner-id",
        &repository_owner_id.get().to_be_bytes(),
    );
    update_digest_field(
        &mut digest,
        b"identity:repository-visibility",
        match identity.repository_visibility() {
            ProviderRepositoryVisibility::Public => b"public",
            ProviderRepositoryVisibility::Private => b"private",
        },
    );
    update_digest_field(
        &mut digest,
        b"identity:repository",
        identity.repository_identity().as_bytes(),
    );
    update_digest_field(
        &mut digest,
        b"identity:delivery-id",
        identity.delivery_id().as_bytes(),
    );

    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

struct AuthenticatedEventCoordinates {
    event: GithubAuthenticatedEvent,
    head_sha: GithubCheckHeadSha,
}

fn authenticated_event_coordinates(
    event: &VerifiedGithubWebhook,
) -> Result<AuthenticatedEventCoordinates, GithubDeliveryIngressError> {
    let (kind, git_ref, revision) = match event {
        VerifiedGithubWebhook::Push(push) => {
            let revision = if push.deleted() {
                push.before_commit_sha()
            } else {
                push.after_commit_sha()
            };
            (
                GithubAuthenticatedEventKind::Push,
                push.git_ref().full().to_owned(),
                revision,
            )
        }
        VerifiedGithubWebhook::PullRequest(pull_request) => (
            GithubAuthenticatedEventKind::PullRequest,
            pull_request.git_ref().to_owned(),
            pull_request.head_revision().as_str(),
        ),
        VerifiedGithubWebhook::MergeGroup(merge_group) => (
            GithubAuthenticatedEventKind::MergeGroup,
            merge_group.head_ref().full().to_owned(),
            merge_group.head_revision().as_str(),
        ),
        _ => return Err(GithubDeliveryIngressError::InvariantViolation),
    };
    let event = GithubAuthenticatedEvent::new(kind, git_ref)
        .map_err(|_| GithubDeliveryIngressError::InvariantViolation)?;
    Ok(AuthenticatedEventCoordinates {
        event,
        head_sha: check_head_sha_from_revision(revision)?,
    })
}

#[cfg(test)]
fn check_head_sha(
    push: &VerifiedGithubPush,
) -> Result<GithubCheckHeadSha, GithubDeliveryIngressError> {
    let value = if push.deleted() {
        push.before_commit_sha()
    } else {
        push.after_commit_sha()
    };
    check_head_sha_from_revision(value)
}

fn check_head_sha_from_revision(
    value: &str,
) -> Result<GithubCheckHeadSha, GithubDeliveryIngressError> {
    let bytes = value.as_bytes();
    if bytes.len() != 40 {
        return Err(GithubDeliveryIngressError::InvariantViolation);
    }
    let mut decoded = [0_u8; 20];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    GithubCheckHeadSha::new(decoded).map_err(|_| GithubDeliveryIngressError::InvariantViolation)
}

const fn decode_hex_nibble(value: u8) -> Result<u8, GithubDeliveryIngressError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(GithubDeliveryIngressError::InvariantViolation),
    }
}

const fn provider_visibility(
    visibility: GithubRepositoryVisibility,
) -> ProviderRepositoryVisibility {
    match visibility {
        GithubRepositoryVisibility::Public => ProviderRepositoryVisibility::Public,
        GithubRepositoryVisibility::Private => ProviderRepositoryVisibility::Private,
    }
}

fn update_digest_field(digest: &mut Sha256, label: &[u8], value: &[u8]) {
    let label_length = u16::try_from(label.len()).expect("fixed digest label fits in u16");
    let value_length = u64::try_from(value.len()).expect("bounded digest field fits in u64");
    digest.update(label_length.to_be_bytes());
    digest.update(label);
    digest.update(value_length.to_be_bytes());
    digest.update(value);
}

fn verified_header<'headers>(
    headers: &'headers HeaderMap,
    name: &'static str,
) -> Result<&'headers [u8], GithubDeliveryIngressError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or(GithubDeliveryIngressError::InvariantViolation)?;
    if values.next().is_some() {
        return Err(GithubDeliveryIngressError::InvariantViolation);
    }
    Ok(value.as_bytes())
}

fn validate_repository_component(value: &str) -> Result<(), GithubDeliveryConfigurationError> {
    if value.is_empty()
        || value.len() > MAX_REPOSITORY_COMPONENT_BYTES
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(GithubDeliveryConfigurationError::InvalidRepositoryIdentity);
    }
    Ok(())
}

fn valid_default_branch_ref(value: &str) -> bool {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    value.len() <= 1_024
        && !(branch.is_empty()
            || branch == "@"
            || branch.starts_with(['-', '/', '.'])
            || branch.ends_with(['/', '.'])
            || branch.contains("..")
            || branch.contains("@{")
            || branch.contains("//")
            || branch.split('/').any(|component| {
                component.is_empty()
                    || component.starts_with('.')
                    || component.as_bytes().ends_with(b".lock")
            })
            || branch.chars().any(|character| {
                character.is_control()
                    || character.is_whitespace()
                    || matches!(character, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
            }))
}

fn has_ascii_case_insensitive_suffix(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix))
}

#[cfg(test)]
mod tests;
