use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_store::{
    AcceptProviderDelivery, AdmissionObject, ClaimProviderDelivery, ClaimedProviderDelivery,
    MAX_ADMISSION_EVENT_BYTES, MAX_ADMISSION_OBJECT_BYTES, MAX_PROVIDER_DELIVERY_ATTEMPTS,
    MAX_PROVIDER_DELIVERY_CLAIM_MILLIS, MAX_PROVIDER_DELIVERY_RETRY_BACKOFF_MILLIS,
    MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS, ObjectKey, ProviderConnectionId,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId, ProviderDeliveryFailureKind,
    ProviderDeliveryId, ProviderDeliveryIdentity, ProviderDeliveryReceipt,
    ProviderDeliveryRenewalTiming, ProviderDeliveryState, ProviderDeliveryValueError,
    ProviderDeliveryWorkflowConclusion, ProviderDeliveryWorkflowOutcome, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, RenewProviderDeliveryClaim, RenewedProviderDeliveryClaim,
    TenantScope,
};
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

const PROVIDER_DELIVERY_MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

fn identity() -> ProviderDeliveryIdentity {
    ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        "github",
        ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("connection"),
        ProviderInstallationId::new(41).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(42).expect("repository"),
            ProviderRepositoryVisibility::Private,
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        "delivery-1",
    )
    .expect("identity")
}

fn raw_event() -> AdmissionObject {
    AdmissionObject::new_event(
        Sha256Digest::from_bytes([7; 32]),
        ObjectKey::new("provider-events/github/delivery-1").expect("object key"),
        512,
        "application/json",
    )
    .expect("raw event")
}

#[test]
fn provider_event_and_standard_object_ceilings_remain_distinct() {
    let descriptor = |size| {
        (
            Sha256Digest::from_bytes([11; 32]),
            ObjectKey::new(format!("provider-events/limit/{size}")).expect("object key"),
            size,
            "application/json",
        )
    };
    let (digest, key, size, media) = descriptor(MAX_ADMISSION_OBJECT_BYTES + 1);
    assert!(AdmissionObject::new(digest, key, size, media).is_err());
    let (digest, key, size, media) = descriptor(MAX_ADMISSION_OBJECT_BYTES + 1);
    assert!(AdmissionObject::new_event(digest, key, size, media).is_ok());
    let (digest, key, size, media) = descriptor(MAX_ADMISSION_EVENT_BYTES);
    assert!(AdmissionObject::new_event(digest, key, size, media).is_ok());
    let (digest, key, size, media) = descriptor(MAX_ADMISSION_EVENT_BYTES + 1);
    assert!(AdmissionObject::new_event(digest, key, size, media).is_err());
}

#[test]
fn provider_authority_rejects_sentinels_and_unbounded_values() {
    assert!(matches!(
        ProviderConnectionId::from_uuid(Uuid::nil()),
        Err(ProviderDeliveryValueError::NilUuid(
            "provider connection ID"
        ))
    ));
    assert!(matches!(
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::nil()),
        Err(ProviderDeliveryValueError::NilUuid(
            "provider delivery claim owner ID"
        ))
    ));
    assert!(matches!(
        ProviderInstallationId::new(0),
        Err(ProviderDeliveryValueError::InvalidNumericId(
            "provider installation ID"
        ))
    ));
    assert!(matches!(
        ProviderRepositoryId::new(u64::MAX),
        Err(ProviderDeliveryValueError::InvalidNumericId(
            "provider repository ID"
        ))
    ));
    assert!(matches!(
        ProviderRepositoryOwnerId::new(0),
        Err(ProviderDeliveryValueError::InvalidNumericId(
            "provider repository owner ID"
        ))
    ));

    let invalid_provider = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        "github webhook",
        ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("connection"),
        ProviderInstallationId::new(1).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(2).expect("repository"),
            ProviderRepositoryVisibility::Private,
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        "delivery-1",
    );
    assert!(matches!(
        invalid_provider,
        Err(ProviderDeliveryValueError::InvalidMachineIdentifier(
            "provider"
        ))
    ));

    let untrimmed_delivery = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        "github",
        ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("connection"),
        ProviderInstallationId::new(1).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(2).expect("repository"),
            ProviderRepositoryVisibility::Private,
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        " delivery-1",
    );
    assert!(matches!(
        untrimmed_delivery,
        Err(ProviderDeliveryValueError::EmptyOrUntrimmed(
            "provider delivery ID"
        ))
    ));
}

#[test]
fn acceptance_retains_only_bounded_immutable_object_evidence() {
    let request = AcceptProviderDelivery::new(
        identity(),
        Sha256Digest::from_bytes([9; 32]),
        raw_event(),
        UnixMillis::new(100),
    )
    .expect("acceptance");
    assert_eq!(request.identity().provider(), "github");
    assert_eq!(request.identity().repository_id().get(), 42);
    assert_eq!(
        request.identity().repository_visibility(),
        ProviderRepositoryVisibility::Private
    );
    assert_eq!(request.identity().delivery_id(), "delivery-1");
    assert_eq!(request.raw_event().encoded_size(), 512);
    assert_eq!(request.accepted_at(), UnixMillis::new(100));

    assert!(matches!(
        AcceptProviderDelivery::new(
            identity(),
            Sha256Digest::from_bytes([9; 32]),
            raw_event(),
            UnixMillis::new(-1),
        ),
        Err(ProviderDeliveryValueError::NegativeTimestamp(
            "provider delivery acceptance time"
        ))
    ));
}

#[test]
fn claims_and_retry_classifications_are_strictly_bounded() {
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4()).expect("owner");
    let claim = ClaimProviderDelivery::new(
        owner,
        UnixMillis::new(1_000),
        UnixMillis::new(1_000 + MAX_PROVIDER_DELIVERY_CLAIM_MILLIS),
    )
    .expect("maximum claim");
    assert_eq!(claim.owner(), owner);
    assert!(matches!(
        ClaimProviderDelivery::new(
            owner,
            UnixMillis::new(1_000),
            UnixMillis::new(1_001 + MAX_PROVIDER_DELIVERY_CLAIM_MILLIS),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        ClaimProviderDelivery::new(owner, UnixMillis::new(1_000), UnixMillis::new(1_000)),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));

    let failure = ProviderDeliveryFailureKind::new("provider.rate_limited").expect("failure");
    assert_eq!(failure.as_str(), "provider.rate_limited");
    assert!(matches!(
        ProviderDeliveryFailureKind::new("upstream said: secret text"),
        Err(ProviderDeliveryValueError::InvalidMachineIdentifier(
            "failure kind"
        ))
    ));
    assert_eq!(MAX_PROVIDER_DELIVERY_RETRY_BACKOFF_MILLIS, 86_400_000);
    assert_eq!(MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS, 3_600_000);
}

#[test]
fn durable_claim_rehydration_revalidates_receipt_fence_and_time() {
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::new_v4()).expect("delivery");
    let other_delivery_id = ProviderDeliveryId::from_uuid(Uuid::new_v4()).expect("other delivery");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4()).expect("owner");
    let receipt = ProviderDeliveryReceipt::from_durable_parts(
        delivery_id,
        ProviderDeliveryState::Claimed,
        1,
        UnixMillis::new(100),
    )
    .expect("claimed receipt");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 7).expect("claim fence");
    let claimed = ClaimedProviderDelivery::from_durable_parts(
        receipt,
        identity(),
        Sha256Digest::from_bytes([9; 32]),
        raw_event(),
        claim,
        UnixMillis::new(200),
        UnixMillis::new(300),
    )
    .expect("claimed delivery");
    assert_eq!(claimed.receipt(), receipt);
    assert_eq!(claimed.claim(), claim);
    assert_eq!(claimed.attempt(), 1);

    let mismatched = ProviderDeliveryClaimFence::from_durable_parts(other_delivery_id, owner, 8)
        .expect("mismatched claim fence");
    assert!(matches!(
        ClaimedProviderDelivery::from_durable_parts(
            receipt,
            identity(),
            Sha256Digest::from_bytes([9; 32]),
            raw_event(),
            mismatched,
            UnixMillis::new(200),
            UnixMillis::new(300),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimReceipt)
    ));
    assert!(matches!(
        ClaimedProviderDelivery::from_durable_parts(
            receipt,
            identity(),
            Sha256Digest::from_bytes([9; 32]),
            raw_event(),
            claim,
            UnixMillis::new(99),
            UnixMillis::new(300),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimReceipt)
    ));
    let completed_receipt = ProviderDeliveryReceipt::from_durable_parts(
        delivery_id,
        ProviderDeliveryState::Completed,
        1,
        UnixMillis::new(100),
    )
    .expect("completed receipt");
    assert!(matches!(
        ClaimedProviderDelivery::from_durable_parts(
            completed_receipt,
            identity(),
            Sha256Digest::from_bytes([9; 32]),
            raw_event(),
            claim,
            UnixMillis::new(200),
            UnixMillis::new(300),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimReceipt)
    ));
    assert!(matches!(
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 0),
        Err(ProviderDeliveryValueError::InvalidClaimFence)
    ));
}

#[test]
fn durable_renewal_rehydration_revalidates_rotated_fence_and_bounded_time() {
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::new_v4()).expect("delivery");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4()).expect("owner");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 9).expect("claim fence");
    let renewed = RenewedProviderDeliveryClaim::from_durable_parts(
        claim,
        4,
        UnixMillis::new(200),
        UnixMillis::new(250),
        UnixMillis::new(350),
    )
    .expect("renewed claim");
    assert_eq!(renewed.claim(), claim);
    assert_eq!(renewed.attempt(), 4);
    assert_eq!(renewed.claimed_at(), UnixMillis::new(200));
    assert_eq!(renewed.renewed_at(), UnixMillis::new(250));
    assert_eq!(renewed.expires_at(), UnixMillis::new(350));

    assert!(matches!(
        RenewedProviderDeliveryClaim::from_durable_parts(
            claim,
            4,
            UnixMillis::new(-1),
            UnixMillis::new(250),
            UnixMillis::new(350),
        ),
        Err(ProviderDeliveryValueError::NegativeTimestamp(
            "durable provider delivery claim time"
        ))
    ));
    assert!(matches!(
        RenewedProviderDeliveryClaim::from_durable_parts(
            claim,
            4,
            UnixMillis::new(200),
            UnixMillis::new(199),
            UnixMillis::new(350),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        RenewedProviderDeliveryClaim::from_durable_parts(
            claim,
            4,
            UnixMillis::new(200),
            UnixMillis::new(200),
            UnixMillis::new(350),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        RenewedProviderDeliveryClaim::from_durable_parts(
            claim,
            4,
            UnixMillis::new(200),
            UnixMillis::new(250),
            UnixMillis::new(250),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        RenewedProviderDeliveryClaim::from_durable_parts(
            claim,
            4,
            UnixMillis::new(200),
            UnixMillis::new(250),
            UnixMillis::new(250 + MAX_PROVIDER_DELIVERY_CLAIM_MILLIS + 1),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        RenewedProviderDeliveryClaim::from_durable_parts(
            claim,
            4,
            UnixMillis::new(200),
            UnixMillis::new(200 + MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS - 1),
            UnixMillis::new(200 + MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS + 1),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        RenewedProviderDeliveryClaim::from_durable_parts(
            claim,
            0,
            UnixMillis::new(200),
            UnixMillis::new(250),
            UnixMillis::new(350),
        ),
        Err(ProviderDeliveryValueError::InvalidAttempt)
    ));
    assert!(matches!(
        RenewedProviderDeliveryClaim::from_durable_parts(
            claim,
            MAX_PROVIDER_DELIVERY_ATTEMPTS + 1,
            UnixMillis::new(200),
            UnixMillis::new(250),
            UnixMillis::new(350),
        ),
        Err(ProviderDeliveryValueError::InvalidAttempt)
    ));
}

#[test]
fn renewal_request_binds_the_exact_predecessor_to_one_monotonic_deadline() {
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::new_v4()).expect("delivery");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4()).expect("owner");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 9).expect("claim");
    let monotonic_observed_at = Instant::now();
    let confirmed_predecessor_deadline = monotonic_observed_at + Duration::from_millis(450);
    let timing = ProviderDeliveryRenewalTiming::new(
        confirmed_predecessor_deadline,
        monotonic_observed_at,
        UnixMillis::new(1_100),
        UnixMillis::new(1_600),
    )
    .expect("renewal timing");
    let request = RenewProviderDeliveryClaim::new(
        claim,
        4,
        UnixMillis::new(1_000),
        timing,
        UnixMillis::new(1_700),
    )
    .expect("renewal request");

    assert_eq!(request.claim(), claim);
    assert_eq!(request.attempt(), 4);
    assert_eq!(request.claimed_at(), UnixMillis::new(1_000));
    assert_eq!(request.observed_at(), UnixMillis::new(1_100));
    assert_eq!(request.predecessor_expires_at(), UnixMillis::new(1_600));
    assert_eq!(request.expires_at(), UnixMillis::new(1_700));
    assert_eq!(
        request.deadline().duration_since(monotonic_observed_at),
        Duration::from_millis(450),
        "the fresh wall-clock observation must not widen a confirmed deadline",
    );
    let wall_clock_cap = ProviderDeliveryRenewalTiming::new(
        monotonic_observed_at + Duration::from_mins(1),
        monotonic_observed_at,
        UnixMillis::new(1_100),
        UnixMillis::new(1_600),
    )
    .expect("fresh observation caps a later supplied deadline");
    assert_eq!(
        wall_clock_cap
            .deadline()
            .duration_since(monotonic_observed_at),
        Duration::from_millis(500)
    );
}

#[test]
fn renewal_request_rejects_stale_or_inconsistent_evidence() {
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::new_v4()).expect("delivery");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4()).expect("owner");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 9).expect("claim");
    let monotonic_observed_at = Instant::now();
    let timing = ProviderDeliveryRenewalTiming::new(
        monotonic_observed_at + Duration::from_millis(450),
        monotonic_observed_at,
        UnixMillis::new(1_100),
        UnixMillis::new(1_600),
    )
    .expect("renewal timing");
    assert!(matches!(
        ProviderDeliveryRenewalTiming::new(
            monotonic_observed_at + Duration::from_millis(500),
            Instant::now() + Duration::from_mins(1),
            UnixMillis::new(1_100),
            UnixMillis::new(1_600),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        ProviderDeliveryRenewalTiming::new(
            monotonic_observed_at,
            monotonic_observed_at,
            UnixMillis::new(1_100),
            UnixMillis::new(1_600),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));
    let stale_monotonic_observation = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .expect("monotonic test anchor");
    assert!(matches!(
        ProviderDeliveryRenewalTiming::new(
            Instant::now() + Duration::from_mins(1),
            stale_monotonic_observation,
            UnixMillis::new(1_100),
            UnixMillis::new(1_600),
        ),
        Err(ProviderDeliveryValueError::InvalidClaimInterval)
    ));

    for attempt in [0, MAX_PROVIDER_DELIVERY_ATTEMPTS + 1] {
        assert!(matches!(
            RenewProviderDeliveryClaim::new(
                claim,
                attempt,
                UnixMillis::new(1_000),
                timing,
                UnixMillis::new(1_700),
            ),
            Err(ProviderDeliveryValueError::InvalidAttempt)
        ));
    }

    for (claimed_at, expires_at) in [
        (1_100, 1_700),
        (1_000, 1_600),
        (1_000, 1_100 + MAX_PROVIDER_DELIVERY_CLAIM_MILLIS + 1),
        (1_000, 1_000 + MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS + 1),
    ] {
        assert!(matches!(
            RenewProviderDeliveryClaim::new(
                claim,
                4,
                UnixMillis::new(claimed_at),
                timing,
                UnixMillis::new(expires_at),
            ),
            Err(ProviderDeliveryValueError::InvalidClaimInterval)
        ));
    }

    for (observed_at, predecessor_expires_at) in [(1_600, 1_600), (1_100, 1_099)] {
        assert!(matches!(
            ProviderDeliveryRenewalTiming::new(
                monotonic_observed_at + Duration::from_secs(1),
                monotonic_observed_at,
                UnixMillis::new(observed_at),
                UnixMillis::new(predecessor_expires_at),
            ),
            Err(ProviderDeliveryValueError::InvalidClaimInterval)
        ));
    }
}

#[test]
fn current_schema_distinguishes_bounded_renewal_from_crash_reclaim() {
    for required in [
        "renewal_predecessor_expires_at_ms BIGINT",
        "claim_expires_at_ms - state_updated_at_ms <= 900000",
        "claim_expires_at_ms - claimed_at_ms <= 3600000",
        "NEW.claim_fence = OLD.claim_fence + 1",
        "NEW.claimed_at_ms IS NOT DISTINCT FROM OLD.claimed_at_ms",
        "NEW.claim_expires_at_ms <= OLD.claim_expires_at_ms",
        "NEW.state_updated_at_ms <= OLD.state_updated_at_ms",
        "NEW.state_updated_at_ms >= OLD.claim_expires_at_ms",
        "NEW.renewal_predecessor_expires_at_ms\n                    IS DISTINCT FROM OLD.claim_expires_at_ms",
        "provider_delivery_inbox_renewal_transition",
        "provider_delivery_inbox_reclaim_transition",
    ] {
        assert!(
            PROVIDER_DELIVERY_MIGRATION.contains(required),
            "provider-delivery migration lost renewal invariant: {required}",
        );
    }
    assert!(
        !PROVIDER_DELIVERY_MIGRATION
            .contains("AND state_updated_at_ms = claimed_at_ms\n        ) OR ("),
        "the claimed-state shape must permit a rotated-fence renewal timestamp",
    );
}

#[test]
fn current_schema_persists_closed_immutable_repository_visibility() {
    for required in [
        "repository_visibility TEXT COLLATE \"C\" NOT NULL",
        "repository_visibility IN ('public', 'private')",
        "NEW.repository_visibility IS DISTINCT FROM OLD.repository_visibility",
        "provider_delivery_inbox_evidence_immutable",
    ] {
        assert!(
            PROVIDER_DELIVERY_MIGRATION.contains(required),
            "provider-delivery migration lost visibility invariant: {required}",
        );
    }
}

#[test]
fn workflow_outcomes_require_safe_unique_path_candidates() {
    let admitted = ProviderDeliveryWorkflowOutcome::new(
        ".ci/workflows/ci.yml",
        ProviderDeliveryWorkflowConclusion::Admitted {
            run_id: RunId::from_uuid(Uuid::new_v4()),
        },
    )
    .expect("admitted outcome");
    assert_eq!(admitted.workflow_path(), ".ci/workflows/ci.yml");

    for path in [
        "/.ci/workflows/ci.yml",
        ".github/../secret",
        ".github//workflows/ci.yml",
        ".github\\workflows\\ci.yml",
    ] {
        assert!(matches!(
            ProviderDeliveryWorkflowOutcome::new(
                path,
                ProviderDeliveryWorkflowConclusion::Skipped {
                    reason: ProviderDeliveryFailureKind::new("not_selected").expect("reason"),
                },
            ),
            Err(ProviderDeliveryValueError::InvalidWorkflowPath)
        ));
    }
    assert!(matches!(
        ProviderDeliveryWorkflowOutcome::new(
            ".ci/workflows/ci.yml",
            ProviderDeliveryWorkflowConclusion::Admitted {
                run_id: RunId::from_uuid(Uuid::nil()),
            },
        ),
        Err(ProviderDeliveryValueError::NilUuid(
            "provider delivery outcome run ID"
        ))
    ));
}
