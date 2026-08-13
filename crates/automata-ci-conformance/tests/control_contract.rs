use std::sync::{Arc, Mutex};

use automata_ci_conformance::{
    ConformanceClock, DurableTransition, FaultMode, FaultPlan, FaultTarget, FixtureControl,
    FixtureControlError, MAX_CONFORMANCE_SHARDS, ManualConformanceClock, ProductService,
    ServiceObservation, ServiceRestartProbe, ServiceState, ShardPlan,
};

#[derive(Debug)]
struct ProbeState {
    state: ServiceState,
    generation: u64,
    instance: String,
}

#[derive(Debug)]
struct FakeRestartProbe(Mutex<ProbeState>);

impl FakeRestartProbe {
    fn running() -> Self {
        Self(Mutex::new(ProbeState {
            state: ServiceState::Running,
            generation: 7,
            instance: "process-7".to_owned(),
        }))
    }
}

impl ServiceRestartProbe for FakeRestartProbe {
    fn observe(&self, _service: ProductService) -> Result<ServiceObservation, FixtureControlError> {
        let state = self
            .0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        ServiceObservation::new(state.state, state.generation, state.instance.clone())
    }

    fn stop(&self, _service: ProductService) -> Result<(), FixtureControlError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        if state.state != ServiceState::Running {
            return Err(FixtureControlError::ProbeFailed);
        }
        state.state = ServiceState::Stopped;
        Ok(())
    }

    fn start(&self, _service: ProductService) -> Result<(), FixtureControlError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        if state.state != ServiceState::Stopped {
            return Err(FixtureControlError::ProbeFailed);
        }
        state.generation += 1;
        state.instance = format!("process-{}", state.generation);
        state.state = ServiceState::Running;
        Ok(())
    }
}

#[derive(Debug)]
struct LyingRestartProbe;

impl ServiceRestartProbe for LyingRestartProbe {
    fn observe(&self, _service: ProductService) -> Result<ServiceObservation, FixtureControlError> {
        ServiceObservation::new(ServiceState::Running, 1, "same-process")
    }

    fn stop(&self, _service: ProductService) -> Result<(), FixtureControlError> {
        Ok(())
    }

    fn start(&self, _service: ProductService) -> Result<(), FixtureControlError> {
        Ok(())
    }
}

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
            assert_ne!(left.id(), right.id());
            assert_ne!(left.postgres_schema(), right.postgres_schema());
            assert_ne!(left.object_prefix(), right.object_prefix());
            assert_ne!(left.credential_scope(), right.credential_scope());
            assert_ne!(left.port_reservation_key(), right.port_reservation_key());
        }
    }
    assert_eq!(
        ShardPlan::derive("run-2026-08-13", 3).expect("left"),
        ShardPlan::derive("run-2026-08-13", 3).expect("right")
    );
    assert_eq!(
        plan.shard(MAX_CONFORMANCE_SHARDS),
        Err(FixtureControlError::UnknownShard)
    );
}

#[test]
fn restart_is_proven_between_every_durable_transition() {
    let plan = ShardPlan::derive("restart-run", 1).expect("plan");
    let clock = Arc::new(ManualConformanceClock::new(10_000));
    let control =
        FixtureControl::for_shard(Arc::clone(&clock), Arc::new(FaultPlan::default()), &plan, 0)
            .expect("control from derived shard");
    assert_eq!(
        control.transition(DurableTransition::WebhookAccepted),
        Err(FixtureControlError::RestartRequired)
    );

    let probe = FakeRestartProbe::running();
    control
        .restart_with(ProductService::Ingress, &probe)
        .expect("verified restart");
    assert_eq!(
        control.restart_with(ProductService::Ingress, &probe),
        Err(FixtureControlError::DuplicateRestart)
    );
    control
        .transition(DurableTransition::WebhookAccepted)
        .expect("next transition");
    assert_eq!(
        control.current_transition(),
        DurableTransition::WebhookAccepted
    );
    let records = control.restart_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].stopped_generation(), 7);
    assert_eq!(records[0].started_generation(), 8);
    assert_eq!(records[0].stopped_instance(), "process-7");
    assert_eq!(records[0].started_instance(), "process-8");
    assert_eq!(
        control.transition(DurableTransition::WorkflowAdmitted),
        Err(FixtureControlError::NonContiguousTransition)
    );
}

#[test]
fn caller_assertions_cannot_replace_restart_observations() {
    let plan = ShardPlan::derive("lying-restart-run", 1).expect("plan");
    let control = FixtureControl::for_shard(
        Arc::new(ManualConformanceClock::new(0)),
        Arc::new(FaultPlan::default()),
        &plan,
        0,
    )
    .expect("control");
    assert_eq!(
        control.restart_with(ProductService::Runner, &LyingRestartProbe),
        Err(FixtureControlError::RestartDidNotStop)
    );
    assert!(control.restart_records().is_empty());
    assert_eq!(
        control.transition(DurableTransition::WebhookAccepted),
        Err(FixtureControlError::RestartRequired)
    );
}
