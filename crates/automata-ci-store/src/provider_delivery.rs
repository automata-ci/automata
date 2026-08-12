use std::{
    num::{NonZeroU16, NonZeroU64},
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_core::{RunId, UnixMillis};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::time::Instant;
use uuid::Uuid;

use crate::{AdmissionObject, RepositoryOperationError, Sha256Digest, TenantScope};

/// Maximum number of processing attempts for one provider delivery.
pub const MAX_PROVIDER_DELIVERY_ATTEMPTS: u16 = 16;
/// Maximum duration of one provider-delivery claim lease.
pub const MAX_PROVIDER_DELIVERY_CLAIM_MILLIS: i64 = 15 * 60 * 1_000;
/// Maximum total lifetime of one provider-delivery claim attempt across rotated fences.
pub const MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS: i64 = 60 * 60 * 1_000;
/// Maximum delay before a failed delivery becomes eligible again.
pub const MAX_PROVIDER_DELIVERY_RETRY_BACKOFF_MILLIS: i64 = 24 * 60 * 60 * 1_000;
/// Maximum number of terminal workflow outcomes retained for one delivery.
pub const MAX_PROVIDER_DELIVERY_WORKFLOW_OUTCOMES: usize = 256;

const MAX_PROVIDER_BYTES: usize = 128;
const MAX_DELIVERY_ID_BYTES: usize = 255;
const MAX_REPOSITORY_IDENTITY_BYTES: usize = 1_024;
const MAX_FAILURE_KIND_BYTES: usize = 128;
const MAX_WORKFLOW_PATH_BYTES: usize = 1_024;
const COMPLETION_DIGEST_DOMAIN: &[u8] = b"automata.store.provider-delivery-completion.v1\0";

macro_rules! uuid_identity {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Constructs a non-nil durable UUID identity.
            ///
            /// # Errors
            ///
            /// Rejects the nil UUID sentinel.
            pub fn from_uuid(value: Uuid) -> Result<Self, ProviderDeliveryValueError> {
                if value.is_nil() {
                    return Err(ProviderDeliveryValueError::NilUuid($field));
                }
                Ok(Self(value))
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

uuid_identity!(/// Durable identity of one accepted provider delivery.
    ProviderDeliveryId, "provider delivery ID");
uuid_identity!(/// Server-owned identity of one configured provider connection.
    ProviderConnectionId, "provider connection ID");
uuid_identity!(/// Durable identity of a provider-delivery worker.
    ProviderDeliveryClaimOwnerId, "provider delivery claim owner ID");

macro_rules! positive_provider_id {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Constructs a positive provider numeric identity representable by
            /// the durable signed `BIGINT` schema.
            ///
            /// # Errors
            ///
            /// Rejects zero and values larger than `i64::MAX`.
            pub fn new(value: u64) -> Result<Self, ProviderDeliveryValueError> {
                let value = NonZeroU64::new(value)
                    .ok_or(ProviderDeliveryValueError::InvalidNumericId($field))?;
                if i64::try_from(value.get()).is_err() {
                    return Err(ProviderDeliveryValueError::InvalidNumericId($field));
                }
                Ok(Self(value))
            }

            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }

            pub(crate) fn as_i64(self) -> i64 {
                i64::try_from(self.get()).expect("validated provider ID fits in i64")
            }
        }
    };
}

positive_provider_id!(/// Positive provider installation identity.
    ProviderInstallationId, "provider installation ID");
positive_provider_id!(/// Positive provider repository identity.
    ProviderRepositoryId, "provider repository ID");
positive_provider_id!(/// Positive provider repository-owner identity.
    ProviderRepositoryOwnerId, "provider repository owner ID");

/// Closed authenticated visibility of one provider repository.
///
/// This is immutable delivery identity. It is not inferred from source-fetch
/// success or from whether a credential happens to be available.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderRepositoryVisibility {
    /// The authenticated provider event declares a publicly readable repository.
    Public,
    /// The authenticated provider event declares a private repository.
    Private,
}

impl ProviderRepositoryVisibility {
    pub(crate) const fn as_durable_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    pub(crate) fn from_durable_str(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "private" => Some(Self::Private),
            _ => None,
        }
    }
}

/// Exact immutable provider repository coordinates authenticated for a delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRepositoryCoordinates {
    repository_id: ProviderRepositoryId,
    visibility: ProviderRepositoryVisibility,
    identity: String,
}

impl ProviderRepositoryCoordinates {
    /// Constructs one bounded provider-neutral repository identity.
    ///
    /// # Errors
    ///
    /// Rejects empty, untrimmed, control-bearing, or oversized display identity.
    pub fn new(
        repository_id: ProviderRepositoryId,
        visibility: ProviderRepositoryVisibility,
        identity: impl Into<String>,
    ) -> Result<Self, ProviderDeliveryValueError> {
        let identity = identity.into();
        validate_text(
            &identity,
            MAX_REPOSITORY_IDENTITY_BYTES,
            "provider repository identity",
        )?;
        Ok(Self {
            repository_id,
            visibility,
            identity,
        })
    }

    #[must_use]
    pub const fn repository_id(&self) -> ProviderRepositoryId {
        self.repository_id
    }

    #[must_use]
    pub const fn visibility(&self) -> ProviderRepositoryVisibility {
        self.visibility
    }

    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// Exact provider, connection, and repository identity bound to one delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryIdentity {
    tenant: TenantScope,
    provider: String,
    connection_id: ProviderConnectionId,
    installation_id: ProviderInstallationId,
    repository: ProviderRepositoryCoordinates,
    delivery_id: String,
}

impl ProviderDeliveryIdentity {
    /// Constructs bounded server-owned routing and provider replay identity.
    ///
    /// The provider is a canonical machine identifier. The repository identity
    /// is provider-supplied display/routing evidence and is never used as the
    /// stable numeric authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid provider or delivery text.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantScope,
        provider: impl Into<String>,
        connection_id: ProviderConnectionId,
        installation_id: ProviderInstallationId,
        repository: ProviderRepositoryCoordinates,
        delivery_id: impl Into<String>,
    ) -> Result<Self, ProviderDeliveryValueError> {
        let provider = provider.into();
        validate_machine_identifier(&provider, MAX_PROVIDER_BYTES, "provider")?;
        let delivery_id = delivery_id.into();
        validate_text(&delivery_id, MAX_DELIVERY_ID_BYTES, "provider delivery ID")?;
        Ok(Self {
            tenant,
            provider,
            connection_id,
            installation_id,
            repository,
            delivery_id,
        })
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.installation_id
    }

    #[must_use]
    pub const fn repository_id(&self) -> ProviderRepositoryId {
        self.repository.repository_id()
    }

    /// Returns the authenticated immutable repository visibility.
    #[must_use]
    pub const fn repository_visibility(&self) -> ProviderRepositoryVisibility {
        self.repository.visibility()
    }

    #[must_use]
    pub fn repository_identity(&self) -> &str {
        self.repository.identity()
    }

    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }
}

/// Immutable evidence accepted before provider parsing or object reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptProviderDelivery {
    identity: ProviderDeliveryIdentity,
    request_digest: Sha256Digest,
    raw_event: AdmissionObject,
    accepted_at: UnixMillis,
}

impl AcceptProviderDelivery {
    /// Constructs an inbox acceptance request.
    ///
    /// `request_digest` must be computed by trusted ingress over a canonical,
    /// domain-separated encoding of the verified headers, exact body bytes,
    /// and [`ProviderDeliveryIdentity`]. The store deliberately performs no
    /// provider parsing, blob write, or network I/O.
    ///
    /// # Errors
    ///
    /// Rejects a timestamp before the Unix epoch.
    pub fn new(
        identity: ProviderDeliveryIdentity,
        request_digest: Sha256Digest,
        raw_event: AdmissionObject,
        accepted_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        validate_timestamp(accepted_at, "provider delivery acceptance time")?;
        Ok(Self {
            identity,
            request_digest,
            raw_event,
            accepted_at,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &ProviderDeliveryIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    #[must_use]
    pub const fn raw_event(&self) -> &AdmissionObject {
        &self.raw_event
    }

    #[must_use]
    pub const fn accepted_at(&self) -> UnixMillis {
        self.accepted_at
    }
}

/// Durable lifecycle of one provider delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDeliveryState {
    Pending,
    Claimed,
    RetryPending,
    Completed,
    Rejected,
}

/// Stable acceptance receipt returned by both initial and exact replay calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryReceipt {
    id: ProviderDeliveryId,
    state: ProviderDeliveryState,
    attempts: u16,
    accepted_at: UnixMillis,
}

impl ProviderDeliveryReceipt {
    /// Rehydrates one receipt returned by a durable repository adapter.
    ///
    /// The attempt counter is zero only while a delivery is pending. Claimed
    /// and terminal deliveries have attempted processing at least once.
    /// Retry-pending deliveries cannot retain the terminal attempt count,
    /// because the next claim would exceed the fixed retry ceiling.
    ///
    /// # Errors
    ///
    /// Rejects a pre-epoch acceptance timestamp or an attempt counter that is
    /// inconsistent with the durable state.
    pub fn from_durable_parts(
        id: ProviderDeliveryId,
        state: ProviderDeliveryState,
        attempts: u16,
        accepted_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        validate_timestamp(accepted_at, "provider delivery acceptance time")?;
        let attempts_valid = match state {
            ProviderDeliveryState::Pending => attempts == 0,
            ProviderDeliveryState::RetryPending => {
                (1..MAX_PROVIDER_DELIVERY_ATTEMPTS).contains(&attempts)
            }
            ProviderDeliveryState::Claimed
            | ProviderDeliveryState::Completed
            | ProviderDeliveryState::Rejected => {
                (1..=MAX_PROVIDER_DELIVERY_ATTEMPTS).contains(&attempts)
            }
        };
        if !attempts_valid {
            return Err(ProviderDeliveryValueError::InvalidReceiptAttempts);
        }
        Ok(Self {
            id,
            state,
            attempts,
            accepted_at,
        })
    }

    #[must_use]
    pub const fn id(self) -> ProviderDeliveryId {
        self.id
    }

    #[must_use]
    pub const fn state(self) -> ProviderDeliveryState {
        self.state
    }

    #[must_use]
    pub const fn attempts(self) -> u16 {
        self.attempts
    }

    #[must_use]
    pub const fn accepted_at(self) -> UnixMillis {
        self.accepted_at
    }
}

/// Request to claim the next eligible delivery without holding a transaction
/// across provider, blob, compiler, or admission work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimProviderDelivery {
    owner: ProviderDeliveryClaimOwnerId,
    observed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimProviderDelivery {
    /// Constructs a bounded claim lease.
    ///
    /// # Errors
    ///
    /// Rejects negative time, an empty interval, or a lease longer than the
    /// fixed provider-delivery claim bound.
    pub fn new(
        owner: ProviderDeliveryClaimOwnerId,
        observed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        validate_timestamp(observed_at, "provider delivery claim observation")?;
        validate_timestamp(expires_at, "provider delivery claim expiration")?;
        let duration = expires_at
            .get()
            .checked_sub(observed_at.get())
            .filter(|duration| *duration > 0 && *duration <= MAX_PROVIDER_DELIVERY_CLAIM_MILLIS)
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        debug_assert!(duration > 0);
        Ok(Self {
            owner,
            observed_at,
            expires_at,
        })
    }

    #[must_use]
    pub const fn owner(self) -> ProviderDeliveryClaimOwnerId {
        self.owner
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Exact owner/fence proof required by every claimed-state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryClaimFence {
    delivery_id: ProviderDeliveryId,
    owner: ProviderDeliveryClaimOwnerId,
    fence: NonZeroU64,
}

impl ProviderDeliveryClaimFence {
    /// Rehydrates one exact claim fence returned by a durable repository.
    ///
    /// # Errors
    ///
    /// Rejects a zero or signed-database-incompatible fence value.
    pub fn from_durable_parts(
        delivery_id: ProviderDeliveryId,
        owner: ProviderDeliveryClaimOwnerId,
        fence: u64,
    ) -> Result<Self, ProviderDeliveryValueError> {
        let fence = NonZeroU64::new(fence)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .ok_or(ProviderDeliveryValueError::InvalidClaimFence)?;
        Ok(Self {
            delivery_id,
            owner,
            fence,
        })
    }

    #[must_use]
    pub const fn delivery_id(self) -> ProviderDeliveryId {
        self.delivery_id
    }

    #[must_use]
    pub const fn owner(self) -> ProviderDeliveryClaimOwnerId {
        self.owner
    }

    #[must_use]
    pub const fn fence(self) -> u64 {
        self.fence.get()
    }

    pub(crate) fn fence_i64(self) -> i64 {
        i64::try_from(self.fence()).expect("validated provider-delivery fence fits in i64")
    }
}

/// Complete immutable delivery evidence returned under an expiring claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedProviderDelivery {
    receipt: ProviderDeliveryReceipt,
    identity: ProviderDeliveryIdentity,
    request_digest: Sha256Digest,
    raw_event: AdmissionObject,
    claim: ProviderDeliveryClaimFence,
    attempt: NonZeroU16,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl ClaimedProviderDelivery {
    /// Rehydrates complete immutable delivery evidence under a durable claim.
    ///
    /// The receipt must describe this exact claimed delivery, and the claim
    /// time cannot precede acceptance. The claim interval remains subject to
    /// the same fixed bound as a newly requested claim.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent receipt, fence, attempt, or timestamp evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn from_durable_parts(
        receipt: ProviderDeliveryReceipt,
        identity: ProviderDeliveryIdentity,
        request_digest: Sha256Digest,
        raw_event: AdmissionObject,
        claim: ProviderDeliveryClaimFence,
        claimed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        if receipt.state() != ProviderDeliveryState::Claimed
            || receipt.id() != claim.delivery_id()
            || claimed_at.get() < receipt.accepted_at().get()
        {
            return Err(ProviderDeliveryValueError::InvalidClaimReceipt);
        }
        let attempt = NonZeroU16::new(receipt.attempts())
            .filter(|attempt| attempt.get() <= MAX_PROVIDER_DELIVERY_ATTEMPTS)
            .ok_or(ProviderDeliveryValueError::InvalidAttempt)?;
        validate_timestamp(claimed_at, "durable provider delivery claim time")?;
        validate_timestamp(expires_at, "durable provider delivery claim expiration")?;
        expires_at
            .get()
            .checked_sub(claimed_at.get())
            .filter(|duration| *duration > 0 && *duration <= MAX_PROVIDER_DELIVERY_CLAIM_MILLIS)
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        Ok(Self {
            receipt,
            identity,
            request_digest,
            raw_event,
            claim,
            attempt,
            claimed_at,
            expires_at,
        })
    }

    #[must_use]
    pub const fn receipt(&self) -> ProviderDeliveryReceipt {
        self.receipt
    }

    #[must_use]
    pub const fn identity(&self) -> &ProviderDeliveryIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    #[must_use]
    pub const fn raw_event(&self) -> &AdmissionObject {
        &self.raw_event
    }

    #[must_use]
    pub const fn claim(&self) -> ProviderDeliveryClaimFence {
        self.claim
    }

    #[must_use]
    pub const fn attempt(&self) -> u16 {
        self.attempt.get()
    }

    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

/// Trusted paired timing evidence for one provider-delivery renewal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryRenewalTiming {
    observed_at: UnixMillis,
    predecessor_expires_at: UnixMillis,
    deadline: Instant,
}

impl ProviderDeliveryRenewalTiming {
    /// Caps an already-confirmed predecessor deadline against a fresh paired
    /// monotonic and wall-clock observation.
    ///
    /// `monotonic_observed_at` must be captured immediately before
    /// `observed_at`. The confirmed deadline is never widened: a slower or
    /// stepped-back wall clock can only retain or shorten it.
    ///
    /// # Errors
    ///
    /// Rejects negative or inconsistent wall time, a future monotonic sample,
    /// an already-expired confirmed deadline, or monotonic deadline overflow.
    pub fn new(
        confirmed_predecessor_deadline: Instant,
        monotonic_observed_at: Instant,
        observed_at: UnixMillis,
        predecessor_expires_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        let current_monotonic_time = Instant::now();
        if monotonic_observed_at > current_monotonic_time
            || confirmed_predecessor_deadline <= current_monotonic_time
        {
            return Err(ProviderDeliveryValueError::InvalidClaimInterval);
        }
        validate_timestamp(observed_at, "provider delivery renewal observation")?;
        validate_timestamp(
            predecessor_expires_at,
            "provider delivery predecessor expiration",
        )?;
        let predecessor_remaining = predecessor_expires_at
            .get()
            .checked_sub(observed_at.get())
            .filter(|remaining| *remaining > 0 && *remaining <= MAX_PROVIDER_DELIVERY_CLAIM_MILLIS)
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        let observed_deadline = monotonic_observed_at
            .checked_add(Duration::from_millis(
                u64::try_from(predecessor_remaining)
                    .map_err(|_| ProviderDeliveryValueError::InvalidClaimInterval)?,
            ))
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        let deadline = confirmed_predecessor_deadline.min(observed_deadline);
        if deadline <= current_monotonic_time {
            return Err(ProviderDeliveryValueError::InvalidClaimInterval);
        }
        Ok(Self {
            observed_at,
            predecessor_expires_at,
            deadline,
        })
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.observed_at
    }

    #[must_use]
    pub const fn predecessor_expires_at(self) -> UnixMillis {
        self.predecessor_expires_at
    }

    #[must_use]
    pub const fn deadline(self) -> Instant {
        self.deadline
    }
}

/// Exact-fence request to rotate and extend a live provider-delivery claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewProviderDeliveryClaim {
    claim: ProviderDeliveryClaimFence,
    attempt: NonZeroU16,
    claimed_at: UnixMillis,
    timing: ProviderDeliveryRenewalTiming,
    expires_at: UnixMillis,
}

impl RenewProviderDeliveryClaim {
    /// Constructs one bounded claim-renewal request.
    ///
    /// The timing evidence retains an immutable, non-widening predecessor
    /// deadline across retries. The database additionally enforces the total
    /// lifetime measured from the original durable claim time.
    ///
    /// # Errors
    ///
    /// Rejects an invalid attempt, negative or inconsistent time, an expired
    /// predecessor, or an extension interval over 15 minutes.
    pub fn new(
        claim: ProviderDeliveryClaimFence,
        attempt: u16,
        claimed_at: UnixMillis,
        timing: ProviderDeliveryRenewalTiming,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        let attempt = NonZeroU16::new(attempt)
            .filter(|attempt| attempt.get() <= MAX_PROVIDER_DELIVERY_ATTEMPTS)
            .ok_or(ProviderDeliveryValueError::InvalidAttempt)?;
        validate_timestamp(claimed_at, "provider delivery original claim time")?;
        validate_timestamp(expires_at, "provider delivery renewal expiration")?;
        timing
            .observed_at()
            .get()
            .checked_sub(claimed_at.get())
            .filter(|elapsed| *elapsed > 0)
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        expires_at
            .get()
            .checked_sub(timing.predecessor_expires_at().get())
            .filter(|extension| *extension > 0)
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        expires_at
            .get()
            .checked_sub(timing.observed_at().get())
            .filter(|duration| *duration > 0 && *duration <= MAX_PROVIDER_DELIVERY_CLAIM_MILLIS)
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        expires_at
            .get()
            .checked_sub(claimed_at.get())
            .filter(|duration| {
                *duration > 0 && *duration <= MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS
            })
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        Ok(Self {
            claim,
            attempt,
            claimed_at,
            timing,
            expires_at,
        })
    }

    #[must_use]
    pub const fn claim(self) -> ProviderDeliveryClaimFence {
        self.claim
    }

    /// Returns the exact durable attempt preserved by the renewal.
    #[must_use]
    pub const fn attempt(self) -> u16 {
        self.attempt.get()
    }

    /// Returns the immutable original claim time.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    #[must_use]
    pub const fn observed_at(self) -> UnixMillis {
        self.timing.observed_at()
    }

    /// Returns the exact predecessor expiration protected by the deadline.
    #[must_use]
    pub const fn predecessor_expires_at(self) -> UnixMillis {
        self.timing.predecessor_expires_at()
    }

    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }

    /// Returns the immutable process-local deadline for acquiring the exact row lock.
    #[must_use]
    pub const fn deadline(self) -> Instant {
        self.timing.deadline()
    }
}

/// Durable result of an exact provider-delivery claim renewal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewedProviderDeliveryClaim {
    claim: ProviderDeliveryClaimFence,
    attempt: NonZeroU16,
    claimed_at: UnixMillis,
    renewed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl RenewedProviderDeliveryClaim {
    /// Rehydrates one successful rotated-fence renewal returned by a durable adapter.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range attempt, pre-epoch or non-increasing timestamps,
    /// an extension longer than one claim interval, or a total claim lifetime
    /// over one hour.
    pub fn from_durable_parts(
        claim: ProviderDeliveryClaimFence,
        attempt: u16,
        claimed_at: UnixMillis,
        renewed_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        let attempt = NonZeroU16::new(attempt)
            .filter(|attempt| attempt.get() <= MAX_PROVIDER_DELIVERY_ATTEMPTS)
            .ok_or(ProviderDeliveryValueError::InvalidAttempt)?;
        validate_timestamp(claimed_at, "durable provider delivery claim time")?;
        validate_timestamp(renewed_at, "durable provider delivery renewal time")?;
        validate_timestamp(expires_at, "durable provider delivery claim expiration")?;
        renewed_at
            .get()
            .checked_sub(claimed_at.get())
            .filter(|elapsed| *elapsed > 0)
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        let increment = expires_at
            .get()
            .checked_sub(renewed_at.get())
            .filter(|duration| *duration > 0 && *duration <= MAX_PROVIDER_DELIVERY_CLAIM_MILLIS)
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        let total = expires_at
            .get()
            .checked_sub(claimed_at.get())
            .filter(|duration| {
                *duration > 0 && *duration <= MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS
            })
            .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
        debug_assert!(increment > 0 && total > 0);
        Ok(Self {
            claim,
            attempt,
            claimed_at,
            renewed_at,
            expires_at,
        })
    }

    #[must_use]
    pub const fn claim(self) -> ProviderDeliveryClaimFence {
        self.claim
    }

    /// Returns the exact durable attempt preserved by this renewal.
    #[must_use]
    pub const fn attempt(self) -> u16 {
        self.attempt.get()
    }

    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    #[must_use]
    pub const fn renewed_at(self) -> UnixMillis {
        self.renewed_at
    }

    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }
}

/// Sanitized, bounded machine-readable failure classification.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderDeliveryFailureKind(String);

impl ProviderDeliveryFailureKind {
    /// Constructs a canonical failure kind safe to persist and log.
    ///
    /// # Errors
    ///
    /// Rejects values outside `[A-Za-z0-9][A-Za-z0-9._:-]*` or over 128
    /// bytes. Human/provider error text must never be placed in this field.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderDeliveryValueError> {
        let value = value.into();
        validate_machine_identifier(&value, MAX_FAILURE_KIND_BYTES, "failure kind")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Terminal result for one provider-discovered workflow path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderDeliveryWorkflowConclusion {
    Admitted {
        run_id: RunId,
    },
    Skipped {
        reason: ProviderDeliveryFailureKind,
    },
    Failed {
        failure_kind: ProviderDeliveryFailureKind,
    },
}

/// One deterministic, path-keyed terminal workflow outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderDeliveryWorkflowOutcome {
    workflow_path: String,
    conclusion: ProviderDeliveryWorkflowConclusion,
}

impl ProviderDeliveryWorkflowOutcome {
    /// Constructs a bounded workflow outcome.
    ///
    /// # Errors
    ///
    /// Rejects an absolute, traversing, control-bearing, backslash-bearing, or
    /// oversized workflow path and an admitted nil run identity.
    pub fn new(
        workflow_path: impl Into<String>,
        conclusion: ProviderDeliveryWorkflowConclusion,
    ) -> Result<Self, ProviderDeliveryValueError> {
        let workflow_path = workflow_path.into();
        validate_workflow_path(&workflow_path)?;
        if matches!(
            conclusion,
            ProviderDeliveryWorkflowConclusion::Admitted { run_id }
                if run_id.as_uuid().is_nil()
        ) {
            return Err(ProviderDeliveryValueError::NilUuid(
                "provider delivery outcome run ID",
            ));
        }
        Ok(Self {
            workflow_path,
            conclusion,
        })
    }

    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }

    #[must_use]
    pub const fn conclusion(&self) -> &ProviderDeliveryWorkflowConclusion {
        &self.conclusion
    }
}

/// Atomic completion of one exact claimed delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteProviderDelivery {
    claim: ProviderDeliveryClaimFence,
    outcomes: Vec<ProviderDeliveryWorkflowOutcome>,
    completion_digest: Sha256Digest,
    completed_at: UnixMillis,
}

impl CompleteProviderDelivery {
    /// Sorts outcomes by workflow path and rejects duplicate or excessive
    /// entries before any transaction begins. An empty set is valid.
    ///
    /// # Errors
    ///
    /// Rejects more than 256 outcomes, duplicate paths, or negative time.
    pub fn new(
        claim: ProviderDeliveryClaimFence,
        mut outcomes: Vec<ProviderDeliveryWorkflowOutcome>,
        completed_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        validate_timestamp(completed_at, "provider delivery completion time")?;
        if outcomes.len() > MAX_PROVIDER_DELIVERY_WORKFLOW_OUTCOMES {
            return Err(ProviderDeliveryValueError::TooManyWorkflowOutcomes);
        }
        outcomes.sort_unstable_by(|left, right| left.workflow_path.cmp(&right.workflow_path));
        if outcomes
            .windows(2)
            .any(|pair| pair[0].workflow_path == pair[1].workflow_path)
        {
            return Err(ProviderDeliveryValueError::DuplicateWorkflowPath);
        }
        let completion_digest = completion_digest(&outcomes);
        Ok(Self {
            claim,
            outcomes,
            completion_digest,
            completed_at,
        })
    }

    #[must_use]
    pub const fn claim(&self) -> ProviderDeliveryClaimFence {
        self.claim
    }

    #[must_use]
    pub fn outcomes(&self) -> &[ProviderDeliveryWorkflowOutcome] {
        &self.outcomes
    }

    #[must_use]
    pub const fn completion_digest(&self) -> Sha256Digest {
        self.completion_digest
    }

    #[must_use]
    pub const fn completed_at(&self) -> UnixMillis {
        self.completed_at
    }
}

/// Releases a live claim into bounded delayed retry state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryProviderDelivery {
    claim: ProviderDeliveryClaimFence,
    failure_kind: ProviderDeliveryFailureKind,
    observed_at: UnixMillis,
    retry_at: UnixMillis,
}

impl RetryProviderDelivery {
    /// Constructs a positive retry backoff no longer than 24 hours.
    ///
    /// # Errors
    ///
    /// Rejects negative timestamps, non-positive backoff, or excessive delay.
    pub fn new(
        claim: ProviderDeliveryClaimFence,
        failure_kind: ProviderDeliveryFailureKind,
        observed_at: UnixMillis,
        retry_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        validate_timestamp(observed_at, "provider delivery retry observation")?;
        validate_timestamp(retry_at, "provider delivery retry eligibility")?;
        retry_at
            .get()
            .checked_sub(observed_at.get())
            .filter(|backoff| {
                *backoff > 0 && *backoff <= MAX_PROVIDER_DELIVERY_RETRY_BACKOFF_MILLIS
            })
            .ok_or(ProviderDeliveryValueError::InvalidRetryBackoff)?;
        Ok(Self {
            claim,
            failure_kind,
            observed_at,
            retry_at,
        })
    }

    #[must_use]
    pub const fn claim(&self) -> ProviderDeliveryClaimFence {
        self.claim
    }

    #[must_use]
    pub const fn failure_kind(&self) -> &ProviderDeliveryFailureKind {
        &self.failure_kind
    }

    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    #[must_use]
    pub const fn retry_at(&self) -> UnixMillis {
        self.retry_at
    }
}

/// Terminally rejects one delivery under its live claim fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectProviderDelivery {
    claim: ProviderDeliveryClaimFence,
    failure_kind: ProviderDeliveryFailureKind,
    rejected_at: UnixMillis,
}

impl RejectProviderDelivery {
    /// Constructs a sanitized terminal rejection.
    ///
    /// # Errors
    ///
    /// Rejects a timestamp before the Unix epoch.
    pub fn new(
        claim: ProviderDeliveryClaimFence,
        failure_kind: ProviderDeliveryFailureKind,
        rejected_at: UnixMillis,
    ) -> Result<Self, ProviderDeliveryValueError> {
        validate_timestamp(rejected_at, "provider delivery rejection time")?;
        Ok(Self {
            claim,
            failure_kind,
            rejected_at,
        })
    }

    #[must_use]
    pub const fn claim(&self) -> ProviderDeliveryClaimFence {
        self.claim
    }

    #[must_use]
    pub const fn failure_kind(&self) -> &ProviderDeliveryFailureKind {
        &self.failure_kind
    }

    #[must_use]
    pub const fn rejected_at(&self) -> UnixMillis {
        self.rejected_at
    }
}

/// Invalid provider-delivery values rejected outside database transactions.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderDeliveryValueError {
    #[error("{0} must not be empty or contain surrounding whitespace")]
    EmptyOrUntrimmed(&'static str),
    #[error("{0} exceeds its durable byte bound")]
    TooLong(&'static str),
    #[error("{0} must not contain control characters")]
    ControlCharacter(&'static str),
    #[error("{0} is not a canonical machine identifier")]
    InvalidMachineIdentifier(&'static str),
    #[error("{0} must be a positive provider ID representable by BIGINT")]
    InvalidNumericId(&'static str),
    #[error("{0} must not use the nil UUID sentinel")]
    NilUuid(&'static str),
    #[error("{0} must not predate the Unix epoch")]
    NegativeTimestamp(&'static str),
    #[error("provider delivery claim interval is invalid or too long")]
    InvalidClaimInterval,
    #[error("provider delivery claim fence must be positive and representable by BIGINT")]
    InvalidClaimFence,
    #[error("provider delivery attempt is outside the durable bound")]
    InvalidAttempt,
    #[error("provider delivery receipt attempts are inconsistent with its state")]
    InvalidReceiptAttempts,
    #[error("provider delivery claim evidence is inconsistent with its receipt")]
    InvalidClaimReceipt,
    #[error("provider delivery retry backoff is invalid or too long")]
    InvalidRetryBackoff,
    #[error("provider delivery workflow path is not a safe relative path")]
    InvalidWorkflowPath,
    #[error("provider delivery completion contains a duplicate workflow path")]
    DuplicateWorkflowPath,
    #[error("provider delivery completion exceeds the workflow-outcome bound")]
    TooManyWorkflowOutcomes,
}

/// Portable provider-delivery inbox failures with sanitized display strings.
#[derive(Debug, Error)]
pub enum ProviderDeliveryStoreError {
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    #[error("provider delivery replay evidence conflicts with the durable receipt")]
    ReplayConflict,
    #[error("provider delivery claim is stale, expired, or owned by another worker")]
    ClaimRejected,
    #[error("provider delivery retry attempt limit has been reached")]
    RetryLimitReached,
    #[error("provider delivery admitted outcome does not name a run in the inbox tenant")]
    OutcomeRunRejected,
    #[error("provider delivery claim fence is exhausted")]
    FenceExhausted,
    #[error("durable provider delivery data violates an Automata invariant")]
    CorruptData,
}

impl ProviderDeliveryStoreError {
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }
}

/// Durable provider-neutral delivery inbox.
#[async_trait]
pub trait ProviderDeliveryRepository: Send + Sync {
    /// Accepts a new delivery or returns the exact existing receipt. Reusing a
    /// replay key with changed immutable evidence fails closed.
    async fn accept_provider_delivery(
        &self,
        request: AcceptProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError>;

    /// Claims at most one eligible delivery with `SKIP LOCKED` semantics.
    async fn claim_provider_delivery(
        &self,
        request: ClaimProviderDelivery,
    ) -> Result<Option<ClaimedProviderDelivery>, ProviderDeliveryStoreError>;

    /// Atomically stores deterministically sorted zero-or-many workflow
    /// outcomes and closes the exact live claim. An exact retry by the same
    /// terminal claim fence is idempotent.
    async fn complete_provider_delivery(
        &self,
        request: CompleteProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError>;

    /// Releases the exact live claim into bounded delayed retry state.
    async fn retry_provider_delivery(
        &self,
        request: RetryProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError>;

    /// Terminally rejects the exact live claim with a sanitized failure kind.
    async fn reject_provider_delivery(
        &self,
        request: RejectProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError>;
}

/// Least-authority port for extending an already claimed provider delivery.
#[async_trait]
pub trait ProviderDeliveryClaimRenewalRepository: Send + Sync {
    /// Strictly extends the exact live claim only after locking its predecessor
    /// before the request deadline, preserves its attempt, and returns the next
    /// fencing token. An identical lost-response retry may replay the already
    /// committed successor after that predecessor deadline. The total claim
    /// lifetime remains bounded to one hour.
    async fn renew_provider_delivery_claim(
        &self,
        request: RenewProviderDeliveryClaim,
    ) -> Result<RenewedProviderDeliveryClaim, ProviderDeliveryStoreError>;
}

fn validate_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProviderDeliveryValueError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProviderDeliveryValueError::EmptyOrUntrimmed(field));
    }
    if value.len() > maximum {
        return Err(ProviderDeliveryValueError::TooLong(field));
    }
    if value.chars().any(char::is_control) {
        return Err(ProviderDeliveryValueError::ControlCharacter(field));
    }
    Ok(())
}

fn validate_machine_identifier(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProviderDeliveryValueError> {
    validate_text(value, maximum, field)?;
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ProviderDeliveryValueError::InvalidMachineIdentifier(field));
    }
    Ok(())
}

fn validate_workflow_path(value: &str) -> Result<(), ProviderDeliveryValueError> {
    validate_text(
        value,
        MAX_WORKFLOW_PATH_BYTES,
        "provider delivery workflow path",
    )?;
    if value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(ProviderDeliveryValueError::InvalidWorkflowPath);
    }
    Ok(())
}

fn validate_timestamp(
    value: UnixMillis,
    field: &'static str,
) -> Result<(), ProviderDeliveryValueError> {
    if value.get() < 0 {
        return Err(ProviderDeliveryValueError::NegativeTimestamp(field));
    }
    Ok(())
}

fn completion_digest(outcomes: &[ProviderDeliveryWorkflowOutcome]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(COMPLETION_DIGEST_DOMAIN);
    digest.update(
        u64::try_from(outcomes.len())
            .expect("bounded outcome count fits u64")
            .to_be_bytes(),
    );
    for outcome in outcomes {
        update_length_prefixed(&mut digest, outcome.workflow_path.as_bytes());
        match &outcome.conclusion {
            ProviderDeliveryWorkflowConclusion::Admitted { run_id } => {
                digest.update([1]);
                digest.update(run_id.as_uuid().as_bytes());
            }
            ProviderDeliveryWorkflowConclusion::Skipped { reason } => {
                digest.update([2]);
                update_length_prefixed(&mut digest, reason.as_str().as_bytes());
            }
            ProviderDeliveryWorkflowConclusion::Failed { failure_kind } => {
                digest.update([3]);
                update_length_prefixed(&mut digest, failure_kind.as_str().as_bytes());
            }
        }
    }
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("bounded provider-delivery text fits u64")
            .to_be_bytes(),
    );
    digest.update(value);
}
