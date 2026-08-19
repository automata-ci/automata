use std::{fmt, num::NonZeroU16};

use automata_ci_core::UnixMillis;
use automata_ci_provider::{
    MAX_PROVIDER_PROCESSING_ATTEMPTS, ProviderDeliveryId, ProviderProcessingClaimFence,
    ProviderProcessingInvocationId, ProviderProcessingReceipt, ProviderProcessingState,
};
use thiserror::Error;

/// Exact live common processing authority for one provider-trigger admission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthenticatedProviderDeliveryClaim {
    delivery_id: ProviderDeliveryId,
    fence: ProviderProcessingClaimFence,
    attempt: NonZeroU16,
    created_at: UnixMillis,
}

impl AuthenticatedProviderDeliveryClaim {
    /// Binds one immutable trigger delivery and claimed processing receipt to
    /// the latest durable lease fence.
    ///
    /// # Errors
    ///
    /// Rejects non-trigger, non-claimed, or mutually inconsistent evidence.
    pub fn new(
        delivery_id: ProviderDeliveryId,
        receipt: ProviderProcessingReceipt,
        fence: ProviderProcessingClaimFence,
    ) -> Result<Self, AuthenticatedProviderDeliveryClaimError> {
        let attempt = NonZeroU16::new(receipt.attempts())
            .filter(|attempt| attempt.get() <= MAX_PROVIDER_PROCESSING_ATTEMPTS)
            .ok_or(AuthenticatedProviderDeliveryClaimError)?;
        if receipt.state() != ProviderProcessingState::Claimed
            || receipt.cause_delivery_id() != delivery_id
            || receipt.source_delivery_id() != Some(delivery_id)
            || receipt.invocation_id() != fence.invocation_id()
            || fence.claimed_at() < receipt.created_at()
        {
            return Err(AuthenticatedProviderDeliveryClaimError);
        }
        Ok(Self {
            delivery_id,
            fence,
            attempt,
            created_at: receipt.created_at(),
        })
    }

    /// Returns the immutable normalized trigger delivery.
    #[must_use]
    pub const fn delivery_id(self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns the common processing invocation holding the claim.
    #[must_use]
    pub const fn invocation_id(self) -> ProviderProcessingInvocationId {
        self.fence.invocation_id()
    }

    /// Returns the exact latest durable fence.
    #[must_use]
    pub const fn fence(self) -> ProviderProcessingClaimFence {
        self.fence
    }

    /// Returns the positive processing attempt.
    #[must_use]
    pub const fn attempt(self) -> u16 {
        self.attempt.get()
    }

    /// Returns the immutable processing invocation creation time.
    #[must_use]
    pub const fn created_at(self) -> UnixMillis {
        self.created_at
    }

    /// Reports whether the fence authorizes a mutation at this observation.
    #[must_use]
    pub fn authorizes(self, observed_at: UnixMillis) -> bool {
        observed_at >= self.fence.claimed_at() && observed_at < self.fence.expires_at()
    }
}

impl fmt::Debug for AuthenticatedProviderDeliveryClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedProviderDeliveryClaim([REDACTED])")
    }
}

/// Invalid or inconsistent common provider admission authority.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("provider delivery admission claim is invalid")]
pub struct AuthenticatedProviderDeliveryClaimError;

#[cfg(test)]
mod tests {
    use super::*;
    use automata_ci_provider::{ProviderProcessingState, ProviderProcessingWorkerId};
    use uuid::Uuid;

    fn delivery(value: u128) -> ProviderDeliveryId {
        ProviderDeliveryId::from_uuid(Uuid::from_u128(value)).expect("delivery")
    }

    fn invocation(value: u128) -> ProviderProcessingInvocationId {
        ProviderProcessingInvocationId::from_uuid(Uuid::from_u128(value)).expect("invocation")
    }

    #[test]
    fn claim_requires_one_exact_claimed_trigger_invocation() {
        let source_delivery = delivery(1);
        let invocation = invocation(2);
        let receipt = ProviderProcessingReceipt::new(
            invocation,
            source_delivery,
            Some(source_delivery),
            ProviderProcessingState::Claimed,
            1,
            UnixMillis::new(10),
        )
        .expect("receipt");
        let fence = ProviderProcessingClaimFence::new(
            invocation,
            ProviderProcessingWorkerId::from_uuid(Uuid::from_u128(3)).expect("worker"),
            1,
            UnixMillis::new(11),
            UnixMillis::new(20),
        )
        .expect("fence");
        let claim = AuthenticatedProviderDeliveryClaim::new(source_delivery, receipt, fence)
            .expect("common claim");
        assert!(claim.authorizes(UnixMillis::new(19)));
        assert!(!claim.authorizes(UnixMillis::new(20)));
        assert_eq!(claim.delivery_id(), source_delivery);

        assert!(
            AuthenticatedProviderDeliveryClaim::new(delivery(4), receipt, fence).is_err(),
            "a different source delivery must not acquire admission authority"
        );
    }
}
