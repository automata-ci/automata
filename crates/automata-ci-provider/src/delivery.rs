//! Replay-safe provider delivery inbox and worker ports.

use std::{fmt, future::Future, num::NonZeroU64, pin::Pin};

use automata_ci_core::{Sha256Digest, UnixMillis};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ExternalDeliveryIdentity, ProviderConnectionManifest, ProviderDeliveryId,
    ProviderDeliveryRejection, ProviderDeliveryWorkerId, ProviderLifecycleState,
    ProviderSaveOutcome, ProviderWebhookEndpointId, ProviderWebhookEndpointManifest,
    ProviderWebhookEndpointRevision, ProviderWebhookError, ProviderWebhookSecretCandidates,
    RejectedProviderDelivery, VerifiedProviderDelivery,
};

/// Maximum processing attempts for one admitted provider delivery.
pub const MAX_PROVIDER_DELIVERY_ATTEMPTS: u16 = 16;
/// Maximum duration of one delivery worker lease.
pub const MAX_PROVIDER_DELIVERY_LEASE_MILLIS: i64 = 15 * 60 * 1_000;
/// Maximum total lifetime of one delivery claim across all renewals.
pub const MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS: i64 = 60 * 60 * 1_000;
/// Maximum delay before a transiently failed delivery becomes eligible again.
pub const MAX_PROVIDER_DELIVERY_RETRY_MILLIS: i64 = 24 * 60 * 60 * 1_000;

const DELIVERY_FINGERPRINT_DOMAIN: &[u8] = b"automata.provider.delivery-fingerprint.v1\0";

/// Decrypted endpoint record returned only at trusted delivery ingress.
pub struct ProviderWebhookEndpointRecord {
    manifest: ProviderWebhookEndpointManifest,
    connection: ProviderConnectionManifest,
    secrets: ProviderWebhookSecretCandidates,
}

impl ProviderWebhookEndpointRecord {
    /// Binds an endpoint to its exact active connection and move-only candidates.
    ///
    /// # Errors
    ///
    /// Rejects a connection from another identity or revision.
    pub fn new(
        manifest: ProviderWebhookEndpointManifest,
        connection: ProviderConnectionManifest,
        secrets: ProviderWebhookSecretCandidates,
    ) -> Result<Self, ProviderWebhookError> {
        let configuration = connection.configuration();
        if connection.connection_id() != manifest.connection_id()
            || connection.revision() != manifest.connection_revision()
            || connection.state() != ProviderLifecycleState::Active
            || configuration.repository().instance_id() != manifest.instance_id()
            || configuration.provider_revision() != manifest.provider_revision()
        {
            return Err(ProviderWebhookError::EndpointConnectionMismatch);
        }
        Ok(Self {
            manifest,
            connection,
            secrets,
        })
    }

    /// Returns endpoint routing and verification policy.
    #[must_use]
    pub const fn manifest(&self) -> &ProviderWebhookEndpointManifest {
        &self.manifest
    }

    /// Returns the exact repository connection and adapter policy.
    #[must_use]
    pub const fn connection(&self) -> &ProviderConnectionManifest {
        &self.connection
    }

    /// Returns exact plaintext candidates at the authentication boundary.
    #[must_use]
    pub const fn secrets(&self) -> &ProviderWebhookSecretCandidates {
        &self.secrets
    }

    /// Consumes the record into policy and secret custody values.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProviderWebhookEndpointManifest,
        ProviderConnectionManifest,
        ProviderWebhookSecretCandidates,
    ) {
        (self.manifest, self.connection, self.secrets)
    }
}

impl fmt::Debug for ProviderWebhookEndpointRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWebhookEndpointRecord")
            .field("manifest", &self.manifest)
            .field("connection", &self.connection)
            .field("secrets", &self.secrets)
            .finish()
    }
}

/// Complete authenticated provider delivery retained by the generic inbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderDelivery {
    /// A complete normalized trigger eligible for workflow admission.
    Trigger(Box<VerifiedProviderDelivery>),
    /// An authenticated unknown, unsupported, incomplete, or conflicting event.
    Rejected(Box<RejectedProviderDelivery>),
}

impl ProviderDelivery {
    /// Returns the server-owned delivery identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        match self {
            Self::Trigger(value) => value.delivery_id(),
            Self::Rejected(value) => value.delivery_id(),
        }
    }

    /// Returns instance-scoped provider replay identity.
    #[must_use]
    pub const fn external_delivery(&self) -> &ExternalDeliveryIdentity {
        match self {
            Self::Trigger(value) => value.external_delivery(),
            Self::Rejected(value) => value.external_delivery(),
        }
    }

    /// Returns the endpoint identity used for ingress.
    #[must_use]
    pub const fn endpoint_id(&self) -> ProviderWebhookEndpointId {
        match self {
            Self::Trigger(value) => value.endpoint_id(),
            Self::Rejected(value) => value.endpoint_id(),
        }
    }

    /// Returns the exact raw-body digest.
    #[must_use]
    pub const fn raw_body_digest(&self) -> Sha256Digest {
        match self {
            Self::Trigger(value) => value.raw_body().digest(),
            Self::Rejected(value) => value.raw_body().digest(),
        }
    }

    /// Returns trusted ingress receipt time.
    #[must_use]
    pub const fn received_at(&self) -> UnixMillis {
        match self {
            Self::Trigger(value) => value.received_at(),
            Self::Rejected(value) => value.received_at(),
        }
    }

    /// Computes immutable replay evidence independent of receipt time, server
    /// delivery UUID, endpoint revision, and accepted rotation generation.
    #[must_use]
    pub fn replay_fingerprint(&self) -> ProviderDeliveryReplayFingerprint {
        let mut hash = Sha256::new();
        hash.update(DELIVERY_FINGERPRINT_DOMAIN);
        part(
            &mut hash,
            self.external_delivery().instance_id().as_uuid().as_bytes(),
        );
        part(
            &mut hash,
            self.external_delivery().external_id().as_str().as_bytes(),
        );
        part(&mut hash, self.endpoint_id().as_uuid().as_bytes());
        part(&mut hash, self.raw_body_digest().as_bytes());
        match self {
            Self::Trigger(value) => {
                part(&mut hash, b"trigger");
                part(&mut hash, value.event_type().as_str().as_bytes());
                part(
                    &mut hash,
                    value
                        .trigger()
                        .trigger()
                        .target_repository()
                        .identity()
                        .external_id()
                        .as_str()
                        .as_bytes(),
                );
                part(&mut hash, value.trigger().digest().as_bytes());
            }
            Self::Rejected(value) => {
                part(&mut hash, b"rejected");
                part(&mut hash, value.event_type().as_str().as_bytes());
                match value.repository() {
                    Some(repository) => {
                        hash.update([1]);
                        part(&mut hash, repository.external_id().as_str().as_bytes());
                    }
                    None => hash.update([0]),
                }
                part(&mut hash, rejection_name(value.reason()).as_bytes());
            }
        }
        ProviderDeliveryReplayFingerprint(Sha256Digest::from_bytes(hash.finalize().into()))
    }
}

/// Durable inbox acceptance command with server-owned acceptance time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptProviderDelivery {
    delivery: ProviderDelivery,
    accepted_at: UnixMillis,
}

impl AcceptProviderDelivery {
    /// Binds authenticated evidence to its durable acceptance time.
    ///
    /// # Errors
    ///
    /// Rejects acceptance before ingress receipt or before the Unix epoch.
    pub fn new(
        delivery: ProviderDelivery,
        accepted_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryModelError> {
        if accepted_at.get() < 0 || accepted_at < delivery.received_at() {
            return Err(ProviderDeliveryModelError::InvalidAcceptanceTime);
        }
        Ok(Self {
            delivery,
            accepted_at,
        })
    }

    /// Returns immutable authenticated delivery evidence.
    #[must_use]
    pub const fn delivery(&self) -> &ProviderDelivery {
        &self.delivery
    }

    /// Returns trusted durable acceptance time.
    #[must_use]
    pub const fn accepted_at(&self) -> UnixMillis {
        self.accepted_at
    }

    /// Consumes the command into evidence and acceptance time.
    #[must_use]
    pub fn into_parts(self) -> (ProviderDelivery, UnixMillis) {
        (self.delivery, self.accepted_at)
    }
}

/// Domain-separated exact evidence used to distinguish replay from conflict.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProviderDeliveryReplayFingerprint(Sha256Digest);

impl ProviderDeliveryReplayFingerprint {
    /// Returns the fingerprint digest.
    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.0
    }
}

/// Durable provider delivery lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderDeliveryState {
    /// A normalized trigger is ready for a worker.
    Pending,
    /// A previous transient attempt is waiting for its retry deadline.
    RetryPending,
    /// One worker holds a fenced lease.
    Claimed,
    /// Processing finished successfully.
    Completed,
    /// A complete trigger was terminally rejected by processing policy.
    Failed,
    /// Authenticated event evidence was recorded without admission.
    Discarded,
}

/// Durable receipt returned by inbox mutations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryReceipt {
    delivery_id: ProviderDeliveryId,
    state: ProviderDeliveryState,
    attempts: u16,
    accepted_at: UnixMillis,
}

impl ProviderDeliveryReceipt {
    /// Rehydrates a validated durable receipt.
    ///
    /// # Errors
    ///
    /// Rejects negative time, excessive attempts, or state/attempt disagreement.
    pub fn new(
        delivery_id: ProviderDeliveryId,
        state: ProviderDeliveryState,
        attempts: u16,
        accepted_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryModelError> {
        if accepted_at.get() < 0 || attempts > MAX_PROVIDER_DELIVERY_ATTEMPTS {
            return Err(ProviderDeliveryModelError::InvalidReceipt);
        }
        if matches!(
            state,
            ProviderDeliveryState::Pending | ProviderDeliveryState::Discarded
        ) && attempts != 0
        {
            return Err(ProviderDeliveryModelError::InvalidReceipt);
        }
        if matches!(
            state,
            ProviderDeliveryState::RetryPending
                | ProviderDeliveryState::Claimed
                | ProviderDeliveryState::Completed
                | ProviderDeliveryState::Failed
        ) && attempts == 0
        {
            return Err(ProviderDeliveryModelError::InvalidReceipt);
        }
        Ok(Self {
            delivery_id,
            state,
            attempts,
            accepted_at,
        })
    }

    /// Returns the server-owned delivery identity.
    #[must_use]
    pub const fn delivery_id(self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns current durable state.
    #[must_use]
    pub const fn state(self) -> ProviderDeliveryState {
        self.state
    }

    /// Returns the number of claims issued so far.
    #[must_use]
    pub const fn attempts(self) -> u16 {
        self.attempts
    }

    /// Returns initial durable acceptance time.
    #[must_use]
    pub const fn accepted_at(self) -> UnixMillis {
        self.accepted_at
    }
}

/// Result of atomically accepting a delivery replay key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDeliveryAcceptOutcome {
    /// New immutable evidence was inserted.
    Inserted(ProviderDeliveryReceipt),
    /// Exact replay evidence already existed.
    Duplicate(ProviderDeliveryReceipt),
}

/// Bounded request to claim one eligible normalized trigger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimProviderDelivery {
    worker_id: ProviderDeliveryWorkerId,
    claimed_at: UnixMillis,
    lease_millis: NonZeroU64,
}

impl ClaimProviderDelivery {
    /// Constructs a worker claim request.
    ///
    /// # Errors
    ///
    /// Rejects negative time or zero/excessive lease duration.
    pub fn new(
        worker_id: ProviderDeliveryWorkerId,
        claimed_at: UnixMillis,
        lease_millis: u64,
    ) -> Result<Self, ProviderDeliveryModelError> {
        let lease_millis = NonZeroU64::new(lease_millis)
            .filter(|value| value.get() <= MAX_PROVIDER_DELIVERY_LEASE_MILLIS as u64)
            .ok_or(ProviderDeliveryModelError::InvalidLease)?;
        let lease_i64 = i64::try_from(lease_millis.get())
            .map_err(|_| ProviderDeliveryModelError::InvalidLease)?;
        if claimed_at.get() < 0 || claimed_at.get().checked_add(lease_i64).is_none() {
            return Err(ProviderDeliveryModelError::InvalidLease);
        }
        Ok(Self {
            worker_id,
            claimed_at,
            lease_millis,
        })
    }

    /// Returns the worker requesting ownership.
    #[must_use]
    pub const fn worker_id(self) -> ProviderDeliveryWorkerId {
        self.worker_id
    }

    /// Returns trusted claim time.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns requested lease duration.
    #[must_use]
    pub const fn lease_millis(self) -> u64 {
        self.lease_millis.get()
    }
}

/// Exact worker ownership and fencing evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryClaimFence {
    delivery_id: ProviderDeliveryId,
    worker_id: ProviderDeliveryWorkerId,
    token: NonZeroU64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ProviderDeliveryClaimFence {
    /// Rehydrates a positive, unexpired-at-issuance fence.
    ///
    /// # Errors
    ///
    /// Rejects zero token or negative expiry.
    pub fn new(
        delivery_id: ProviderDeliveryId,
        worker_id: ProviderDeliveryWorkerId,
        token: u64,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryModelError> {
        let token = NonZeroU64::new(token)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(ProviderDeliveryModelError::InvalidFence)?;
        if claimed_at.get() < 0
            || expires_at <= claimed_at
            || expires_at.get() - claimed_at.get() > MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS
        {
            return Err(ProviderDeliveryModelError::InvalidFence);
        }
        Ok(Self {
            delivery_id,
            worker_id,
            token,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the claimed delivery.
    #[must_use]
    pub const fn delivery_id(self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns the owning worker.
    #[must_use]
    pub const fn worker_id(self) -> ProviderDeliveryWorkerId {
        self.worker_id
    }

    /// Returns the monotonic fencing token.
    #[must_use]
    pub const fn token(self) -> u64 {
        self.token.get()
    }

    /// Returns trusted lease acquisition time.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the exclusive lease deadline.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// One normalized trigger and its exact live worker fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedProviderDelivery {
    receipt: ProviderDeliveryReceipt,
    delivery: VerifiedProviderDelivery,
    fence: ProviderDeliveryClaimFence,
}

impl ClaimedProviderDelivery {
    /// Rehydrates mutually consistent claim evidence.
    ///
    /// # Errors
    ///
    /// Rejects identity or state disagreement.
    pub fn new(
        receipt: ProviderDeliveryReceipt,
        delivery: VerifiedProviderDelivery,
        fence: ProviderDeliveryClaimFence,
    ) -> Result<Self, ProviderDeliveryModelError> {
        if receipt.state() != ProviderDeliveryState::Claimed
            || receipt.delivery_id() != delivery.delivery_id()
            || receipt.delivery_id() != fence.delivery_id()
        {
            return Err(ProviderDeliveryModelError::InvalidClaim);
        }
        Ok(Self {
            receipt,
            delivery,
            fence,
        })
    }

    /// Returns claimed receipt state.
    #[must_use]
    pub const fn receipt(&self) -> ProviderDeliveryReceipt {
        self.receipt
    }

    /// Returns immutable normalized delivery evidence.
    #[must_use]
    pub const fn delivery(&self) -> &VerifiedProviderDelivery {
        &self.delivery
    }

    /// Returns exact live fencing evidence.
    #[must_use]
    pub const fn fence(&self) -> ProviderDeliveryClaimFence {
        self.fence
    }
}

/// Command that extends one exact live claim without changing its fence token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewProviderDelivery {
    fence: ProviderDeliveryClaimFence,
    renewed_at: UnixMillis,
    lease_millis: NonZeroU64,
}

impl RenewProviderDelivery {
    /// Constructs a strictly extending live-lease renewal.
    ///
    /// # Errors
    ///
    /// Rejects renewal outside the current lease, excessive per-renewal or
    /// total duration, overflow, or a deadline that would not extend the claim.
    pub fn new(
        fence: ProviderDeliveryClaimFence,
        renewed_at: UnixMillis,
        lease_millis: u64,
    ) -> Result<Self, ProviderDeliveryModelError> {
        validate_fenced_time(fence, renewed_at)?;
        let lease_millis = NonZeroU64::new(lease_millis)
            .filter(|value| value.get() <= MAX_PROVIDER_DELIVERY_LEASE_MILLIS as u64)
            .ok_or(ProviderDeliveryModelError::InvalidLease)?;
        let extension = i64::try_from(lease_millis.get())
            .map_err(|_| ProviderDeliveryModelError::InvalidLease)?;
        let expires_at = renewed_at
            .get()
            .checked_add(extension)
            .ok_or(ProviderDeliveryModelError::InvalidLease)?;
        let total_lifetime = expires_at
            .checked_sub(fence.claimed_at().get())
            .ok_or(ProviderDeliveryModelError::InvalidLease)?;
        if expires_at <= fence.expires_at().get()
            || total_lifetime > MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS
        {
            return Err(ProviderDeliveryModelError::InvalidLease);
        }
        Ok(Self {
            fence,
            renewed_at,
            lease_millis,
        })
    }

    /// Returns exact current claim ownership.
    #[must_use]
    pub const fn fence(self) -> ProviderDeliveryClaimFence {
        self.fence
    }

    /// Returns trusted renewal time within the current lease.
    #[must_use]
    pub const fn renewed_at(self) -> UnixMillis {
        self.renewed_at
    }

    /// Returns the replacement lease duration from renewal time.
    #[must_use]
    pub const fn lease_millis(self) -> u64 {
        self.lease_millis.get()
    }
}

/// Sanitized terminal or transient processing failure category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderDeliveryFailure {
    /// A required dependent service was temporarily unavailable.
    DependencyUnavailable,
    /// Current configuration or policy cannot admit the trigger.
    PolicyRejected,
    /// Durable or normalized evidence violated an invariant.
    InvalidEvidence,
}

/// Command that closes an exact live claim successfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteProviderDelivery {
    fence: ProviderDeliveryClaimFence,
    completed_at: UnixMillis,
}

impl CompleteProviderDelivery {
    /// Constructs a completion command.
    ///
    /// # Errors
    ///
    /// Rejects time outside the live lease.
    pub fn new(
        fence: ProviderDeliveryClaimFence,
        completed_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryModelError> {
        validate_fenced_time(fence, completed_at)?;
        Ok(Self {
            fence,
            completed_at,
        })
    }

    /// Returns exact ownership evidence.
    #[must_use]
    pub const fn fence(self) -> ProviderDeliveryClaimFence {
        self.fence
    }

    /// Returns trusted completion time.
    #[must_use]
    pub const fn completed_at(self) -> UnixMillis {
        self.completed_at
    }
}

/// Command that releases an exact live claim into delayed retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryProviderDelivery {
    fence: ProviderDeliveryClaimFence,
    failed_at: UnixMillis,
    retry_at: UnixMillis,
    failure: ProviderDeliveryFailure,
}

impl RetryProviderDelivery {
    /// Constructs a bounded delayed retry.
    ///
    /// # Errors
    ///
    /// Rejects time outside the lease, a nonfuture deadline, or excessive delay.
    pub fn new(
        fence: ProviderDeliveryClaimFence,
        failed_at: UnixMillis,
        retry_at: UnixMillis,
        failure: ProviderDeliveryFailure,
    ) -> Result<Self, ProviderDeliveryModelError> {
        validate_fenced_time(fence, failed_at)?;
        let delay = retry_at
            .get()
            .checked_sub(failed_at.get())
            .ok_or(ProviderDeliveryModelError::InvalidRetry)?;
        if delay <= 0 || delay > MAX_PROVIDER_DELIVERY_RETRY_MILLIS {
            return Err(ProviderDeliveryModelError::InvalidRetry);
        }
        Ok(Self {
            fence,
            failed_at,
            retry_at,
            failure,
        })
    }

    /// Returns exact ownership evidence.
    #[must_use]
    pub const fn fence(self) -> ProviderDeliveryClaimFence {
        self.fence
    }

    /// Returns trusted failure time.
    #[must_use]
    pub const fn failed_at(self) -> UnixMillis {
        self.failed_at
    }

    /// Returns the next eligibility time.
    #[must_use]
    pub const fn retry_at(self) -> UnixMillis {
        self.retry_at
    }

    /// Returns the sanitized failure category.
    #[must_use]
    pub const fn failure(self) -> ProviderDeliveryFailure {
        self.failure
    }
}

/// Command that terminally rejects an exact live claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailProviderDelivery {
    fence: ProviderDeliveryClaimFence,
    failed_at: UnixMillis,
    failure: ProviderDeliveryFailure,
}

impl FailProviderDelivery {
    /// Constructs a terminal processing failure.
    ///
    /// # Errors
    ///
    /// Rejects time outside the live lease.
    pub fn new(
        fence: ProviderDeliveryClaimFence,
        failed_at: UnixMillis,
        failure: ProviderDeliveryFailure,
    ) -> Result<Self, ProviderDeliveryModelError> {
        validate_fenced_time(fence, failed_at)?;
        Ok(Self {
            fence,
            failed_at,
            failure,
        })
    }

    /// Returns exact ownership evidence.
    #[must_use]
    pub const fn fence(self) -> ProviderDeliveryClaimFence {
        self.fence
    }

    /// Returns trusted failure time.
    #[must_use]
    pub const fn failed_at(self) -> UnixMillis {
        self.failed_at
    }

    /// Returns the sanitized failure category.
    #[must_use]
    pub const fn failure(self) -> ProviderDeliveryFailure {
        self.failure
    }
}

/// Boxed future returned by provider delivery repository operations.
pub type ProviderDeliveryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderDeliveryRepositoryError>> + Send + 'a>>;

/// Durable opaque endpoint repository with secret-generation custody.
pub trait ProviderWebhookEndpointRepository: fmt::Debug + Send + Sync {
    /// Atomically stores a first or contiguous endpoint revision.
    fn save_endpoint(
        &self,
        endpoint: ProviderWebhookEndpointManifest,
    ) -> ProviderDeliveryFuture<'_, ProviderSaveOutcome>;

    /// Loads and decrypts the current exact endpoint record.
    fn resolve_endpoint(
        &self,
        endpoint_id: ProviderWebhookEndpointId,
    ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointRecord>>;

    /// Loads and decrypts one exact historical endpoint revision.
    fn load_endpoint(
        &self,
        endpoint_id: ProviderWebhookEndpointId,
        revision: ProviderWebhookEndpointRevision,
    ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointRecord>>;
}

/// Durable replay-safe provider delivery inbox and worker queue.
pub trait ProviderDeliveryRepository: fmt::Debug + Send + Sync {
    /// Inserts new authenticated evidence or returns an exact replay receipt.
    /// Reusing an instance-scoped external delivery ID with a different replay
    /// fingerprint fails closed as [`ProviderDeliveryRepositoryError::ReplayConflict`].
    fn accept_delivery(
        &self,
        request: AcceptProviderDelivery,
    ) -> ProviderDeliveryFuture<'_, ProviderDeliveryAcceptOutcome>;

    /// Loads one durable authenticated delivery by server-owned identity.
    fn load_delivery(
        &self,
        delivery_id: ProviderDeliveryId,
    ) -> ProviderDeliveryFuture<'_, Option<ProviderDelivery>>;

    /// Claims at most one eligible normalized trigger with skip-locked semantics.
    fn claim_delivery(
        &self,
        request: ClaimProviderDelivery,
    ) -> ProviderDeliveryFuture<'_, Option<ClaimedProviderDelivery>>;

    /// Extends one exact live claim while preserving its fencing token.
    fn renew_delivery(
        &self,
        request: RenewProviderDelivery,
    ) -> ProviderDeliveryFuture<'_, ProviderDeliveryClaimFence>;

    /// Closes an exact live claim successfully.
    fn complete_delivery(
        &self,
        request: CompleteProviderDelivery,
    ) -> ProviderDeliveryFuture<'_, ProviderDeliveryReceipt>;

    /// Releases an exact live claim into bounded delayed retry.
    fn retry_delivery(
        &self,
        request: RetryProviderDelivery,
    ) -> ProviderDeliveryFuture<'_, ProviderDeliveryReceipt>;

    /// Terminally fails an exact live claim.
    fn fail_delivery(
        &self,
        request: FailProviderDelivery,
    ) -> ProviderDeliveryFuture<'_, ProviderDeliveryReceipt>;
}

/// Invalid delivery values rejected before repository access.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDeliveryModelError {
    /// Durable acceptance preceded trusted ingress receipt.
    #[error("provider delivery acceptance time is invalid")]
    InvalidAcceptanceTime,
    /// Receipt state, attempts, or time evidence disagreed.
    #[error("provider delivery receipt is invalid")]
    InvalidReceipt,
    /// Claim lease time or duration was invalid.
    #[error("provider delivery lease is invalid")]
    InvalidLease,
    /// Fencing token or expiry was invalid.
    #[error("provider delivery claim fence is invalid")]
    InvalidFence,
    /// Claimed receipt, delivery, and fence identities disagreed.
    #[error("claimed provider delivery evidence is inconsistent")]
    InvalidClaim,
    /// Completion or failure time was outside the exact live lease.
    #[error("provider delivery fenced mutation time is invalid")]
    InvalidFencedTime,
    /// Retry deadline was nonfuture or beyond the hard delay bound.
    #[error("provider delivery retry deadline is invalid")]
    InvalidRetry,
}

/// Sanitized durable endpoint or delivery repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDeliveryRepositoryError {
    /// Endpoint revision was stale, noncontiguous, or disagreed with durable bytes.
    #[error("provider webhook endpoint revision conflicts with durable state")]
    EndpointConflict,
    /// Referenced instance, connection, secret, endpoint, or delivery was absent.
    #[error("provider delivery reference does not exist")]
    NotFound,
    /// An external delivery replay key was reused with different immutable evidence.
    #[error("provider delivery replay evidence conflicts with durable state")]
    ReplayConflict,
    /// A claim fence was stale, expired, or owned by another worker.
    #[error("provider delivery claim was rejected")]
    ClaimRejected,
    /// The hard attempt bound was reached.
    #[error("provider delivery attempt limit was reached")]
    AttemptLimitReached,
    /// Durable rows violated provider model invariants.
    #[error("provider delivery storage is corrupt")]
    Corrupt,
    /// The durable repository was unavailable.
    #[error("provider delivery repository is unavailable")]
    Unavailable,
}

fn validate_fenced_time(
    fence: ProviderDeliveryClaimFence,
    timestamp: UnixMillis,
) -> Result<(), ProviderDeliveryModelError> {
    if timestamp < fence.claimed_at() || timestamp >= fence.expires_at() {
        return Err(ProviderDeliveryModelError::InvalidFencedTime);
    }
    Ok(())
}

fn part(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

const fn rejection_name(rejection: ProviderDeliveryRejection) -> &'static str {
    match rejection {
        ProviderDeliveryRejection::UnknownEvent => "unknown-event",
        ProviderDeliveryRejection::UnsupportedEvent => "unsupported-event",
        ProviderDeliveryRejection::IncompleteEvent => "incomplete-event",
        ProviderDeliveryRejection::PayloadIdentityMismatch => "payload-identity-mismatch",
        ProviderDeliveryRejection::InvalidPayload => "invalid-payload",
    }
}
