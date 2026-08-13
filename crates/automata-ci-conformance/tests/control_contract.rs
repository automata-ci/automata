use std::sync::Arc;

use automata_ci_conformance::{
    ConformanceClock, DurableTransition, FaultMode, FaultPlan, FaultTarget, FixtureControl,
    FixtureControlError, MAX_CONFORMANCE_SHARDS, ManualConformanceClock, ProductService, ShardPlan,
};

#[test]
fn manual_clock_is_monotonic_and_overflow_safe() {
    let clock = ManualConformanceClock::new(1_000);
    assert_eq!(clock.now_millis(), 1_000);
    assert_eq!(clock.advance(25), Ok(1_025));
    assert_eq!(clock.now_millis(), 1_025);
    assert_eq!(
        clock.advance(0),
        Err(FixtureControlError::InvalidClockAdvance)
    );
    let overflow = ManualConformanceClock::new(i64::MAX);
    assert_eq!(overflow.advance(1), Err(FixtureControlError::ClockOverflow));
}

#[test]
fn every_external_boundary_has_independent_one_shot_faults() {
    let targets = [
        FaultTarget::Source,
        FaultTarget::Token,
        FaultTarget::Results,
        FaultTarget::Checks,
        FaultTarget::Runner,
        FaultTarget::ObjectStorage,
    ];
    let plan = FaultPlan::new(
        targets
            .into_iter()
            .map(|target| (target, FaultMode::Unavailable)),
    )
    .expect("fault plan");
    assert_eq!(plan.remaining(), targets.len());
    for target in targets {
        assert_eq!(plan.take(target), Some(FaultMode::Unavailable));
        assert_eq!(plan.take(target), None);
    }
    assert_eq!(plan.remaining(), 0);
}

#[test]
fn shards_have_no_shared_rows_objects_credentials_or_port_keys() {
    let plan =
        ShardPlan::derive("run-2026-08-13", MAX_CONFORMANCE_SHARDS).expect("maximum shard plan");
    let shards = plan.shards();
    assert_eq!(shards.len(), usize::from(MAX_CONFORMANCE_SHARDS));
    for (index, left) in shards.iter().enumerate() {
        for right in &shards[index + 1..] {
            assert_ne!(left.id, right.id);
            assert_ne!(left.postgres_schema, right.postgres_schema);
            assert_ne!(left.object_prefix, right.object_prefix);
            assert_ne!(left.credential_scope, right.credential_scope);
            assert_ne!(left.port_reservation_key, right.port_reservation_key);
        }
    }
    assert_eq!(
        ShardPlan::derive("run-2026-08-13", 3).expect("left"),
        ShardPlan::derive("run-2026-08-13", 3).expect("right")
    );
}

#[test]
fn restart_is_required_between_every_durable_transition() {
    let shard = ShardPlan::derive("restart-run", 1).expect("plan").shards()[0].clone();
    let clock = Arc::new(ManualConformanceClock::new(10_000));
    let control = FixtureControl::new(Arc::clone(&clock), Arc::new(FaultPlan::default()), shard);
    assert_eq!(
        control.transition(DurableTransition::WebhookAccepted),
        Err(FixtureControlError::RestartRequired)
    );
    control.restarted(ProductService::Ingress).expect("restart");
    assert_eq!(
        control.restarted(ProductService::Ingress),
        Err(FixtureControlError::DuplicateRestart)
    );
    control
        .transition(DurableTransition::WebhookAccepted)
        .expect("next transition");
    assert_eq!(
        control.current_transition(),
        DurableTransition::WebhookAccepted
    );
    assert_eq!(control.restart_records().len(), 1);
    assert_eq!(
        control.transition(DurableTransition::WorkflowAdmitted),
        Err(FixtureControlError::NonContiguousTransition)
    );
}
