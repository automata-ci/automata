mod support;

use std::time::Duration;

use automata_ci_core::RunnerId;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_runtime::{
    LeaseWatchdog, MonotonicMillis, RetryPolicy, RunnerRuntimeConfig, RunnerRuntimeConfigError,
    RunnerRuntimeError, RunnerRuntimeLimits, RuntimeIdSource, StableIdDomain, SystemRuntimeIds,
};
use static_assertions::assert_obj_safe;

#[test]
fn retry_backoff_is_bounded_and_saturating() {
    let retry = RetryPolicy::new(8, Duration::from_millis(10), Duration::from_millis(35))
        .expect("valid retry policy");
    assert_eq!(retry.delay_after(1), Duration::from_millis(10));
    assert_eq!(retry.delay_after(2), Duration::from_millis(20));
    assert_eq!(retry.delay_after(3), Duration::from_millis(35));
    assert_eq!(retry.delay_after(u16::MAX), Duration::from_millis(35));
    for entropy in [0, 1, u64::MAX / 2, u64::MAX] {
        let jittered = retry.jittered_delay_after(3, entropy);
        assert!(jittered >= Duration::from_micros(17_500));
        assert!(jittered <= Duration::from_millis(35));
    }
    assert!(RetryPolicy::new(0, Duration::from_millis(1), Duration::from_secs(1)).is_err());
    assert!(RetryPolicy::new(1, Duration::ZERO, Duration::from_secs(1)).is_err());
}

#[test]
fn durable_slot_ceiling_is_enforced_at_configuration() {
    let runner_id = RunnerId::new();
    let capabilities = support::capabilities(runner_id, 257);
    assert_eq!(
        RunnerRuntimeConfig::new(
            capabilities,
            ProtocolLimits::default(),
            RunnerRuntimeLimits::default(),
        ),
        Err(RunnerRuntimeConfigError::InvalidSlotCount),
    );
}

#[test]
fn watchdog_uses_monotonic_time_and_never_regresses() {
    let watchdog = LeaseWatchdog::new(MonotonicMillis::new(1_000));
    watchdog.extend_to(MonotonicMillis::new(900));
    assert_eq!(watchdog.deadline(), MonotonicMillis::new(1_000));
    assert!(!watchdog.is_expired_at(MonotonicMillis::new(999)));
    assert!(watchdog.is_expired_at(MonotonicMillis::new(1_000)));
    assert!(!MonotonicMillis::new(999).is_at_or_after(MonotonicMillis::new(1_000)));
    assert!(MonotonicMillis::new(1_000).is_at_or_after(MonotonicMillis::new(1_000)));
    watchdog.extend_to(MonotonicMillis::new(2_000));
    assert_eq!(watchdog.deadline(), MonotonicMillis::new(2_000));
}

#[test]
fn authority_expiry_has_a_distinct_sanitized_runtime_error() {
    assert_eq!(
        RunnerRuntimeError::AuthorityExpired.to_string(),
        "job runtime authority expired locally"
    );
}

#[test]
fn stable_ids_are_domain_separated_and_restart_deterministic() {
    let first = SystemRuntimeIds;
    let second = SystemRuntimeIds;
    let identity = b"non-secret-durable-identity";
    assert_eq!(
        first.stable_operation_id(StableIdDomain::LeaseAcceptance, identity),
        second.stable_operation_id(StableIdDomain::LeaseAcceptance, identity),
    );
    assert_ne!(
        first.stable_operation_id(StableIdDomain::LeaseAcceptance, identity),
        first.stable_operation_id(StableIdDomain::LeaseRejection, identity),
    );
}

assert_obj_safe!(automata_ci_runner_runtime::RunnerRuntimeControlClient);
assert_obj_safe!(automata_ci_runner_runtime::JobExecutor);
assert_obj_safe!(automata_ci_runner_runtime::RuntimeClock);
assert_obj_safe!(automata_ci_runner_runtime::RuntimeSleeper);
assert_obj_safe!(automata_ci_runner_runtime::RuntimeIdSource);
assert_obj_safe!(automata_ci_runner_runtime::ExecutionEvents);
