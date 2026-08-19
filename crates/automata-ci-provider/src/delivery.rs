//! Replay-safe provider delivery evidence and processing-invocation ports.

use std::{collections::BTreeSet, fmt, future::Future, num::NonZeroU64, pin::Pin};

use automata_ci_core::{Sha256Digest, UnixMillis};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ExternalDeliveryIdentity, MAX_PROVIDER_WEBHOOK_CONNECTIONS, ProviderConnectionManifest,
    ProviderDeliveryId, ProviderDeliveryRejection, ProviderLifecycleState,
    ProviderProcessingInvocationId, ProviderProcessingWorkerId, ProviderSaveOutcome,
    ProviderWebhookEndpointId, ProviderWebhookEndpointManifest, ProviderWebhookEndpointRevision,
    ProviderWebhookError, ProviderWebhookSecretCandidates, RejectedProviderDelivery,
    VerifiedProviderControlDelivery, VerifiedProviderTriggerDelivery,
};

/// Maximum processing attempts for one admitted provider delivery.
pub const MAX_PROVIDER_PROCESSING_ATTEMPTS: u16 = 16;
/// Maximum duration of one processing-worker lease.
pub const MAX_PROVIDER_PROCESSING_LEASE_MILLIS: i64 = 15 * 60 * 1_000;
/// Maximum total lifetime of one processing claim across all renewals.
pub const MAX_PROVIDER_PROCESSING_TOTAL_CLAIM_MILLIS: i64 = 60 * 60 * 1_000;
/// Maximum delay before a transiently failed invocation becomes eligible again.
pub const MAX_PROVIDER_PROCESSING_RETRY_MILLIS: i64 = 24 * 60 * 60 * 1_000;
const DELIVERY_FINGERPRINT_DOMAIN: &[u8] = b"automata.provider.delivery-fingerprint.v1\0";

/// Decrypted endpoint record returned only at trusted delivery ingress.
pub struct ProviderWebhookEndpointRecord {
    manifest: ProviderWebhookEndpointManifest,
    connections: Vec<ProviderConnectionManifest>,
    secrets: ProviderWebhookSecretCandidates,
}

impl ProviderWebhookEndpointRecord {
    /// Binds an endpoint to its exact active repository registry and move-only candidates.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, duplicate, inactive, or cross-instance registry.
    pub fn new(
        manifest: ProviderWebhookEndpointManifest,
        mut connections: Vec<ProviderConnectionManifest>,
        secrets: ProviderWebhookSecretCandidates,
    ) -> Result<Self, ProviderWebhookError> {
        connections.sort_by_key(ProviderConnectionManifest::connection_id);
        let mut connection_ids = BTreeSet::new();
        let mut repositories = BTreeSet::new();
        if connections.is_empty()
            || connections.len() > MAX_PROVIDER_WEBHOOK_CONNECTIONS
            || connections.iter().any(|connection| {
                let configuration = connection.configuration();
                connection.state() != ProviderLifecycleState::Active
                    || configuration.repository().instance_id() != manifest.instance_id()
                    || configuration.provider_revision() != manifest.provider_revision()
                    || !connection_ids.insert(connection.connection_id())
                    || !repositories.insert(configuration.repository().clone())
            })
        {
            return Err(ProviderWebhookError::InvalidEndpointConnections);
        }
        Ok(Self {
            manifest,
            connections,
            secrets,
        })
    }

    /// Returns endpoint routing and verification policy.
    #[must_use]
    pub const fn manifest(&self) -> &ProviderWebhookEndpointManifest {
        &self.manifest
    }

    /// Returns active repository connections in canonical identity order.
    #[must_use]
    pub fn connections(&self) -> &[ProviderConnectionManifest] {
        &self.connections
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
        Vec<ProviderConnectionManifest>,
        ProviderWebhookSecretCandidates,
    ) {
        (self.manifest, self.connections, self.secrets)
    }
}

impl fmt::Debug for ProviderWebhookEndpointRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWebhookEndpointRecord")
            .field("manifest", &self.manifest)
            .field("connection_count", &self.connections.len())
            .field("secrets", &self.secrets)
            .finish()
    }
}

/// Complete authenticated provider delivery retained by the generic inbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderDelivery {
    /// A complete normalized trigger eligible for workflow admission.
    Trigger(Box<VerifiedProviderTriggerDelivery>),
    /// An authenticated provider-native control request.
    Control(Box<VerifiedProviderControlDelivery>),
    /// An authenticated unknown, unsupported, incomplete, or conflicting event.
    Rejected(Box<RejectedProviderDelivery>),
}

impl ProviderDelivery {
    /// Returns the server-owned delivery identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        match self {
            Self::Trigger(value) => value.evidence().delivery_id(),
            Self::Control(value) => value.evidence().delivery_id(),
            Self::Rejected(value) => value.evidence().delivery_id(),
        }
    }

    /// Returns instance-scoped provider replay identity.
    #[must_use]
    pub const fn external_delivery(&self) -> &ExternalDeliveryIdentity {
        match self {
            Self::Trigger(value) => value.evidence().external_delivery(),
            Self::Control(value) => value.evidence().external_delivery(),
            Self::Rejected(value) => value.evidence().external_delivery(),
        }
    }

    /// Returns the endpoint identity used for ingress.
    #[must_use]
    pub const fn endpoint_id(&self) -> ProviderWebhookEndpointId {
        match self {
            Self::Trigger(value) => value.evidence().endpoint_id(),
            Self::Control(value) => value.evidence().endpoint_id(),
            Self::Rejected(value) => value.evidence().endpoint_id(),
        }
    }

    /// Returns the exact raw-body digest.
    #[must_use]
    pub const fn raw_body_digest(&self) -> Sha256Digest {
        match self {
            Self::Trigger(value) => value.evidence().raw_body().digest(),
            Self::Control(value) => value.evidence().raw_body().digest(),
            Self::Rejected(value) => value.evidence().raw_body().digest(),
        }
    }

    /// Returns trusted ingress receipt time.
    #[must_use]
    pub const fn received_at(&self) -> UnixMillis {
        match self {
            Self::Trigger(value) => value.evidence().received_at(),
            Self::Control(value) => value.evidence().received_at(),
            Self::Rejected(value) => value.evidence().received_at(),
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
                part(&mut hash, value.evidence().event_type().as_str().as_bytes());
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
            Self::Control(value) => {
                part(&mut hash, b"control");
                part(&mut hash, value.evidence().event_type().as_str().as_bytes());
                part(
                    &mut hash,
                    value
                        .control()
                        .repository()
                        .external_id()
                        .as_str()
                        .as_bytes(),
                );
                part(&mut hash, value.control().digest().as_bytes());
            }
            Self::Rejected(value) => {
                part(&mut hash, b"rejected");
                part(&mut hash, value.evidence().event_type().as_str().as_bytes());
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
    invocation_id: Option<ProviderProcessingInvocationId>,
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
        let invocation_id = matches!(
            delivery,
            ProviderDelivery::Trigger(_) | ProviderDelivery::Control(_)
        )
        .then(ProviderProcessingInvocationId::new);
        Ok(Self {
            delivery,
            invocation_id,
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

    /// Returns the new invocation identity reserved for actionable evidence.
    #[must_use]
    pub const fn invocation_id(&self) -> Option<ProviderProcessingInvocationId> {
        self.invocation_id
    }

    /// Consumes the command into evidence and acceptance time.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProviderDelivery,
        Option<ProviderProcessingInvocationId>,
        UnixMillis,
    ) {
        (self.delivery, self.invocation_id, self.accepted_at)
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

/// Durable lifecycle of one processing invocation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderProcessingState {
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
}

/// Immutable receipt for one accepted provider delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryReceipt {
    delivery_id: ProviderDeliveryId,
    invocation_id: Option<ProviderProcessingInvocationId>,
    accepted_at: UnixMillis,
}

impl ProviderDeliveryReceipt {
    /// Rehydrates delivery acceptance and its optional processing invocation.
    ///
    /// # Errors
    ///
    /// Rejects pre-epoch acceptance evidence.
    pub fn new(
        delivery_id: ProviderDeliveryId,
        invocation_id: Option<ProviderProcessingInvocationId>,
        accepted_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryModelError> {
        if accepted_at.get() < 0 {
            return Err(ProviderDeliveryModelError::InvalidReceipt);
        }
        Ok(Self {
            delivery_id,
            invocation_id,
            accepted_at,
        })
    }

    /// Returns the immutable delivery identity.
    #[must_use]
    pub const fn delivery_id(self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns the invocation created for actionable evidence.
    #[must_use]
    pub const fn invocation_id(self) -> Option<ProviderProcessingInvocationId> {
        self.invocation_id
    }

    /// Returns the durable acceptance timestamp.
    #[must_use]
    pub const fn accepted_at(self) -> UnixMillis {
        self.accepted_at
    }
}

/// Durable receipt returned by processing-invocation mutations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderProcessingReceipt {
    invocation_id: ProviderProcessingInvocationId,
    cause_delivery_id: ProviderDeliveryId,
    source_delivery_id: Option<ProviderDeliveryId>,
    state: ProviderProcessingState,
    attempts: u16,
    created_at: UnixMillis,
}

impl ProviderProcessingReceipt {
    /// Rehydrates a validated durable receipt.
    ///
    /// # Errors
    ///
    /// Rejects negative time, excessive attempts, or state/attempt disagreement.
    pub fn new(
        invocation_id: ProviderProcessingInvocationId,
        cause_delivery_id: ProviderDeliveryId,
        source_delivery_id: Option<ProviderDeliveryId>,
        state: ProviderProcessingState,
        attempts: u16,
        created_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryModelError> {
        if created_at.get() < 0 || attempts > MAX_PROVIDER_PROCESSING_ATTEMPTS {
            return Err(ProviderDeliveryModelError::InvalidReceipt);
        }
        if state == ProviderProcessingState::Pending && attempts != 0 {
            return Err(ProviderDeliveryModelError::InvalidReceipt);
        }
        if matches!(
            state,
            ProviderProcessingState::RetryPending
                | ProviderProcessingState::Claimed
                | ProviderProcessingState::Completed
                | ProviderProcessingState::Failed
        ) && attempts == 0
        {
            return Err(ProviderDeliveryModelError::InvalidReceipt);
        }
        Ok(Self {
            invocation_id,
            cause_delivery_id,
            source_delivery_id,
            state,
            attempts,
            created_at,
        })
    }

    /// Returns the server-owned invocation identity.
    #[must_use]
    pub const fn invocation_id(self) -> ProviderProcessingInvocationId {
        self.invocation_id
    }

    /// Returns the immutable delivery that requested this invocation.
    #[must_use]
    pub const fn cause_delivery_id(self) -> ProviderDeliveryId {
        self.cause_delivery_id
    }

    /// Returns the resolved immutable trigger delivery, if one is already bound.
    #[must_use]
    pub const fn source_delivery_id(self) -> Option<ProviderDeliveryId> {
        self.source_delivery_id
    }

    /// Returns current durable state.
    #[must_use]
    pub const fn state(self) -> ProviderProcessingState {
        self.state
    }

    /// Returns the number of claims issued so far.
    #[must_use]
    pub const fn attempts(self) -> u16 {
        self.attempts
    }

    /// Returns initial durable acceptance time.
    #[must_use]
    pub const fn created_at(self) -> UnixMillis {
        self.created_at
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
pub struct ClaimProviderProcessing {
    worker_id: ProviderProcessingWorkerId,
    claimed_at: UnixMillis,
    lease_millis: NonZeroU64,
}

impl ClaimProviderProcessing {
    /// Constructs a worker claim request.
    ///
    /// # Errors
    ///
    /// Rejects negative time or zero/excessive lease duration.
    pub fn new(
        worker_id: ProviderProcessingWorkerId,
        claimed_at: UnixMillis,
        lease_millis: u64,
    ) -> Result<Self, ProviderDeliveryModelError> {
        let lease_millis = NonZeroU64::new(lease_millis)
            .filter(|value| value.get() <= MAX_PROVIDER_PROCESSING_LEASE_MILLIS as u64)
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
    pub const fn worker_id(self) -> ProviderProcessingWorkerId {
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
pub struct ProviderProcessingClaimFence {
    invocation_id: ProviderProcessingInvocationId,
    worker_id: ProviderProcessingWorkerId,
    token: NonZeroU64,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ProviderProcessingClaimFence {
    /// Rehydrates a positive, unexpired-at-issuance fence.
    ///
    /// # Errors
    ///
    /// Rejects zero token or negative expiry.
    pub fn new(
        invocation_id: ProviderProcessingInvocationId,
        worker_id: ProviderProcessingWorkerId,
        token: u64,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryModelError> {
        let token = NonZeroU64::new(token)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(ProviderDeliveryModelError::InvalidFence)?;
        if claimed_at.get() < 0
            || expires_at <= claimed_at
            || expires_at.get() - claimed_at.get() > MAX_PROVIDER_PROCESSING_TOTAL_CLAIM_MILLIS
        {
            return Err(ProviderDeliveryModelError::InvalidFence);
        }
        Ok(Self {
            invocation_id,
            worker_id,
            token,
            claimed_at,
            expires_at,
        })
    }

    /// Returns the claimed processing invocation.
    #[must_use]
    pub const fn invocation_id(self) -> ProviderProcessingInvocationId {
        self.invocation_id
    }

    /// Returns the owning worker.
    #[must_use]
    pub const fn worker_id(self) -> ProviderProcessingWorkerId {
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

/// Immutable actionable input that caused or supplies one processing invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderProcessingInput {
    /// A normalized trigger ready for admission.
    Trigger(Box<VerifiedProviderTriggerDelivery>),
    /// An authenticated control whose trigger target must be resolved exactly.
    Control(Box<VerifiedProviderControlDelivery>),
}

impl ProviderProcessingInput {
    /// Returns the input delivery identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        match self {
            Self::Trigger(value) => value.evidence().delivery_id(),
            Self::Control(value) => value.evidence().delivery_id(),
        }
    }
}

/// One actionable input and its exact live worker fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedProviderProcessing {
    receipt: ProviderProcessingReceipt,
    input: ProviderProcessingInput,
    fence: ProviderProcessingClaimFence,
}

impl ClaimedProviderProcessing {
    /// Rehydrates mutually consistent claim evidence.
    ///
    /// # Errors
    ///
    /// Rejects identity or state disagreement.
    pub fn new(
        receipt: ProviderProcessingReceipt,
        input: ProviderProcessingInput,
        fence: ProviderProcessingClaimFence,
    ) -> Result<Self, ProviderDeliveryModelError> {
        let identity_is_consistent = match &input {
            ProviderProcessingInput::Trigger(delivery) => {
                receipt.source_delivery_id() == Some(delivery.evidence().delivery_id())
            }
            ProviderProcessingInput::Control(delivery) => {
                receipt.source_delivery_id().is_none()
                    && receipt.cause_delivery_id() == delivery.evidence().delivery_id()
            }
        };
        if receipt.state() != ProviderProcessingState::Claimed
            || !identity_is_consistent
            || receipt.invocation_id() != fence.invocation_id()
        {
            return Err(ProviderDeliveryModelError::InvalidClaim);
        }
        Ok(Self {
            receipt,
            input,
            fence,
        })
    }

    /// Returns claimed receipt state.
    #[must_use]
    pub const fn receipt(&self) -> ProviderProcessingReceipt {
        self.receipt
    }

    /// Returns the immutable actionable input.
    #[must_use]
    pub const fn input(&self) -> &ProviderProcessingInput {
        &self.input
    }

    /// Returns exact live fencing evidence.
    #[must_use]
    pub const fn fence(&self) -> ProviderProcessingClaimFence {
        self.fence
    }
}

/// Exact-fence command that resolves an unresolved control to one trigger delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindProviderProcessingSource {
    fence: ProviderProcessingClaimFence,
    source_delivery_id: ProviderDeliveryId,
    bound_at: UnixMillis,
}

impl BindProviderProcessingSource {
    /// Constructs a source binding under a live processing claim.
    ///
    /// # Errors
    ///
    /// Rejects a binding timestamp outside the exact live lease.
    pub fn new(
        fence: ProviderProcessingClaimFence,
        source_delivery_id: ProviderDeliveryId,
        bound_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryModelError> {
        validate_fenced_time(fence, bound_at)?;
        Ok(Self {
            fence,
            source_delivery_id,
            bound_at,
        })
    }

    /// Returns exact live claim ownership.
    #[must_use]
    pub const fn fence(self) -> ProviderProcessingClaimFence {
        self.fence
    }

    /// Returns the resolved immutable trigger delivery.
    #[must_use]
    pub const fn source_delivery_id(self) -> ProviderDeliveryId {
        self.source_delivery_id
    }

    /// Returns trusted resolution time.
    #[must_use]
    pub const fn bound_at(self) -> UnixMillis {
        self.bound_at
    }
}

/// Command that extends one exact live claim without changing its fence token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewProviderProcessing {
    fence: ProviderProcessingClaimFence,
    renewed_at: UnixMillis,
    lease_millis: NonZeroU64,
}

impl RenewProviderProcessing {
    /// Constructs a strictly extending live-lease renewal.
    ///
    /// # Errors
    ///
    /// Rejects renewal outside the current lease, excessive per-renewal or
    /// total duration, overflow, or a deadline that would not extend the claim.
    pub fn new(
        fence: ProviderProcessingClaimFence,
        renewed_at: UnixMillis,
        lease_millis: u64,
    ) -> Result<Self, ProviderDeliveryModelError> {
        validate_fenced_time(fence, renewed_at)?;
        let lease_millis = NonZeroU64::new(lease_millis)
            .filter(|value| value.get() <= MAX_PROVIDER_PROCESSING_LEASE_MILLIS as u64)
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
            || total_lifetime > MAX_PROVIDER_PROCESSING_TOTAL_CLAIM_MILLIS
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
    pub const fn fence(self) -> ProviderProcessingClaimFence {
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
pub enum ProviderProcessingFailure {
    /// A required dependent service was temporarily unavailable.
    DependencyUnavailable,
    /// Current configuration or policy cannot admit the trigger.
    PolicyRejected,
    /// Durable or normalized evidence violated an invariant.
    InvalidEvidence,
}

/// Command that closes an exact live claim successfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteProviderProcessing {
    fence: ProviderProcessingClaimFence,
    completed_at: UnixMillis,
}

impl CompleteProviderProcessing {
    /// Constructs a completion command.
    ///
    /// # Errors
    ///
    /// Rejects time outside the live lease.
    pub fn new(
        fence: ProviderProcessingClaimFence,
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
    pub const fn fence(self) -> ProviderProcessingClaimFence {
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
pub struct RetryProviderProcessing {
    fence: ProviderProcessingClaimFence,
    failed_at: UnixMillis,
    retry_at: UnixMillis,
    failure: ProviderProcessingFailure,
}

impl RetryProviderProcessing {
    /// Constructs a bounded delayed retry.
    ///
    /// # Errors
    ///
    /// Rejects time outside the lease, a nonfuture deadline, or excessive delay.
    pub fn new(
        fence: ProviderProcessingClaimFence,
        failed_at: UnixMillis,
        retry_at: UnixMillis,
        failure: ProviderProcessingFailure,
    ) -> Result<Self, ProviderDeliveryModelError> {
        validate_fenced_time(fence, failed_at)?;
        let delay = retry_at
            .get()
            .checked_sub(failed_at.get())
            .ok_or(ProviderDeliveryModelError::InvalidRetry)?;
        if delay <= 0 || delay > MAX_PROVIDER_PROCESSING_RETRY_MILLIS {
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
    pub const fn fence(self) -> ProviderProcessingClaimFence {
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
    pub const fn failure(self) -> ProviderProcessingFailure {
        self.failure
    }
}

/// Command that terminally rejects an exact live claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailProviderProcessing {
    fence: ProviderProcessingClaimFence,
    failed_at: UnixMillis,
    failure: ProviderProcessingFailure,
}

impl FailProviderProcessing {
    /// Constructs a terminal processing failure.
    ///
    /// # Errors
    ///
    /// Rejects time outside the live lease.
    pub fn new(
        fence: ProviderProcessingClaimFence,
        failed_at: UnixMillis,
        failure: ProviderProcessingFailure,
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
    pub const fn fence(self) -> ProviderProcessingClaimFence {
        self.fence
    }

    /// Returns trusted failure time.
    #[must_use]
    pub const fn failed_at(self) -> UnixMillis {
        self.failed_at
    }

    /// Returns the sanitized failure category.
    #[must_use]
    pub const fn failure(self) -> ProviderProcessingFailure {
        self.failure
    }
}

/// Boxed future returned by provider delivery repository operations.
pub type ProviderDeliveryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderDeliveryRepositoryError>> + Send + 'a>>;

/// Boxed future returned by processing-invocation repository operations.
pub type ProviderProcessingFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderProcessingRepositoryError>> + Send + 'a>>;

/// Read-only live source of the latest durably renewed processing fence.
pub trait ProviderProcessingClaimSource: fmt::Debug + Send + Sync {
    /// Returns the latest exact claim fence committed by the processing worker.
    fn current_fence(&self) -> ProviderProcessingClaimFence;
}

/// Durable opaque endpoint repository with secret-generation custody.
pub trait ProviderWebhookEndpointRepository: fmt::Debug + Send + Sync {
    /// Atomically stores a first or contiguous endpoint revision.
    fn save_endpoint(
        &self,
        endpoint: ProviderWebhookEndpointManifest,
    ) -> ProviderDeliveryFuture<'_, ProviderSaveOutcome>;

    /// Loads the current endpoint manifest without requiring active connections
    /// or decrypting its verification candidates.
    fn current_endpoint_manifest(
        &self,
        endpoint_id: ProviderWebhookEndpointId,
    ) -> ProviderDeliveryFuture<'_, Option<ProviderWebhookEndpointManifest>>;

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

/// Durable replay-safe immutable provider delivery inbox.
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
}

/// Durable queue of processing invocations derived from immutable deliveries.
pub trait ProviderProcessingRepository: fmt::Debug + Send + Sync {
    /// Claims at most one eligible processing invocation with skip-locked semantics.
    fn claim_processing(
        &self,
        request: ClaimProviderProcessing,
    ) -> ProviderProcessingFuture<'_, Option<ClaimedProviderProcessing>>;

    /// Binds one unresolved control invocation to an immutable trigger exactly once.
    fn bind_processing_source(
        &self,
        request: BindProviderProcessingSource,
    ) -> ProviderProcessingFuture<'_, ClaimedProviderProcessing>;

    /// Extends one exact live claim while preserving its fencing token.
    fn renew_processing(
        &self,
        request: RenewProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingClaimFence>;

    /// Closes an exact live claim successfully.
    fn complete_processing(
        &self,
        request: CompleteProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt>;

    /// Releases an exact live claim into bounded delayed retry.
    fn retry_processing(
        &self,
        request: RetryProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt>;

    /// Terminally fails an exact live claim.
    fn fail_processing(
        &self,
        request: FailProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt>;
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
    #[error("provider processing claim fence is invalid")]
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
    /// Durable rows violated provider model invariants.
    #[error("provider delivery storage is corrupt")]
    Corrupt,
    /// The durable repository was unavailable.
    #[error("provider delivery repository is unavailable")]
    Unavailable,
}

/// Sanitized durable processing-invocation repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderProcessingRepositoryError {
    /// A referenced processing invocation or source delivery does not exist.
    #[error("provider processing reference does not exist")]
    NotFound,
    /// A processing claim fence was stale, expired, or owned by another worker.
    #[error("provider processing claim was rejected")]
    ClaimRejected,
    /// The hard processing attempt bound was reached.
    #[error("provider processing attempt limit was reached")]
    AttemptLimitReached,
    /// Durable rows violated processing model invariants.
    #[error("provider processing storage is corrupt")]
    Corrupt,
    /// The durable processing repository was unavailable.
    #[error("provider processing repository is unavailable")]
    Unavailable,
}

fn validate_fenced_time(
    fence: ProviderProcessingClaimFence,
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
