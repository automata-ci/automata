use automata_ci_core::UnixMillis;
use automata_ci_store::{
    MAX_PROVIDER_DELIVERY_ATTEMPTS, ProviderDeliveryId, ProviderDeliveryReceipt,
    ProviderDeliveryState, ProviderDeliveryValueError,
};
use uuid::Uuid;

fn delivery_id() -> ProviderDeliveryId {
    ProviderDeliveryId::from_uuid(Uuid::from_u128(0xb06ac530_3295_4f07_9c67_d05080261cd8))
        .expect("fixture delivery ID is non-nil")
}

#[test]
fn durable_receipt_rehydration_accepts_every_reachable_state_boundary() {
    let valid = [
        (ProviderDeliveryState::Pending, 0),
        (ProviderDeliveryState::Claimed, 1),
        (
            ProviderDeliveryState::Claimed,
            MAX_PROVIDER_DELIVERY_ATTEMPTS,
        ),
        (ProviderDeliveryState::RetryPending, 1),
        (
            ProviderDeliveryState::RetryPending,
            MAX_PROVIDER_DELIVERY_ATTEMPTS - 1,
        ),
        (ProviderDeliveryState::Completed, 1),
        (
            ProviderDeliveryState::Completed,
            MAX_PROVIDER_DELIVERY_ATTEMPTS,
        ),
        (ProviderDeliveryState::Rejected, 1),
        (
            ProviderDeliveryState::Rejected,
            MAX_PROVIDER_DELIVERY_ATTEMPTS,
        ),
    ];

    for (state, attempts) in valid {
        let receipt = ProviderDeliveryReceipt::from_durable_parts(
            delivery_id(),
            state,
            attempts,
            UnixMillis::new(0),
        )
        .expect("reachable state and attempt count are valid");
        assert_eq!(receipt.id(), delivery_id());
        assert_eq!(receipt.state(), state);
        assert_eq!(receipt.attempts(), attempts);
        assert_eq!(receipt.accepted_at(), UnixMillis::new(0));
    }
}

#[test]
fn durable_receipt_rehydration_rejects_every_unreachable_attempt_boundary() {
    let invalid = [
        (ProviderDeliveryState::Pending, 1),
        (
            ProviderDeliveryState::Pending,
            MAX_PROVIDER_DELIVERY_ATTEMPTS,
        ),
        (ProviderDeliveryState::Claimed, 0),
        (
            ProviderDeliveryState::Claimed,
            MAX_PROVIDER_DELIVERY_ATTEMPTS + 1,
        ),
        (ProviderDeliveryState::RetryPending, 0),
        (
            ProviderDeliveryState::RetryPending,
            MAX_PROVIDER_DELIVERY_ATTEMPTS,
        ),
        (
            ProviderDeliveryState::RetryPending,
            MAX_PROVIDER_DELIVERY_ATTEMPTS + 1,
        ),
        (ProviderDeliveryState::Completed, 0),
        (
            ProviderDeliveryState::Completed,
            MAX_PROVIDER_DELIVERY_ATTEMPTS + 1,
        ),
        (ProviderDeliveryState::Rejected, 0),
        (
            ProviderDeliveryState::Rejected,
            MAX_PROVIDER_DELIVERY_ATTEMPTS + 1,
        ),
    ];

    for (state, attempts) in invalid {
        assert_eq!(
            ProviderDeliveryReceipt::from_durable_parts(
                delivery_id(),
                state,
                attempts,
                UnixMillis::new(1),
            ),
            Err(ProviderDeliveryValueError::InvalidReceiptAttempts)
        );
    }
}

#[test]
fn durable_receipt_rehydration_rejects_pre_epoch_acceptance() {
    assert_eq!(
        ProviderDeliveryReceipt::from_durable_parts(
            delivery_id(),
            ProviderDeliveryState::Pending,
            0,
            UnixMillis::new(-1),
        ),
        Err(ProviderDeliveryValueError::NegativeTimestamp(
            "provider delivery acceptance time"
        ))
    );
}
