use std::{
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use automata_ci_conformance::{
    ConformanceClock, DurableTransition, FaultMode, FaultOperation, FaultPlan, FaultTarget,
    FixtureControl, FixtureControlError, MAX_CONFORMANCE_SHARDS, ManualConformanceClock,
    ProductService, ServiceObservation, ServiceRestartProbe, ServiceState, ShardPlan,
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

#[derive(Debug)]
struct ReentrantObservationProbe {
    control: Arc<FixtureControl>,
    inner: FakeRestartProbe,
}

impl ServiceRestartProbe for ReentrantObservationProbe {
    fn observe(&self, service: ProductService) -> Result<ServiceObservation, FixtureControlError> {
        let control = Arc::clone(&self.control);
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = sender.send(control.transition(DurableTransition::WebhookAccepted));
        });
        let transition = receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        if transition != Err(FixtureControlError::RestartInProgress) {
            return Err(FixtureControlError::ProbeFailed);
        }
        self.inner.observe(service)
    }

    fn stop(&self, service: ProductService) -> Result<(), FixtureControlError> {
        self.inner.stop(service)
    }

    fn start(&self, service: ProductService) -> Result<(), FixtureControlError> {
        self.inner.start(service)
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
fn every_external_operation_has_checkpoint_specific_one_shot_faults() {
    let entries = [
        (
            FaultOperation::SourceFetch,
            DurableTransition::DeliverySelected,
        ),
        (FaultOperation::TokenIssue, DurableTransition::JobQueued),
        (
            FaultOperation::ResultsFinalization,
            DurableTransition::RunFinalized,
        ),
        (
            FaultOperation::ChecksCredential,
            DurableTransition::ResultsPublished,
        ),
        (
            FaultOperation::RunnerSync,
            DurableTransition::LeaseCommitted,
        ),
        (
            FaultOperation::ObjectWrite,
            DurableTransition::JobResultCommitted,
        ),
    ];
    let plan = FaultPlan::new(
        entries
            .into_iter()
            .map(|(operation, transition)| (operation, transition, FaultMode::Unavailable)),
    )
    .expect("fault plan");
    assert_eq!(plan.remaining(), entries.len());
    for (operation, transition) in entries {
        assert_eq!(
            operation.target(),
            match operation {
                FaultOperation::SourceFetch => FaultTarget::Source,
                FaultOperation::TokenIssue => FaultTarget::Token,
                FaultOperation::ResultsFinalization => FaultTarget::Results,
                FaultOperation::ChecksCredential => FaultTarget::Checks,
                FaultOperation::RunnerSync => FaultTarget::Runner,
                FaultOperation::ObjectWrite => FaultTarget::ObjectStorage,
                _ => unreachable!("closed test operation"),
            }
        );
        assert_eq!(
            plan.take_due(operation, transition),
            Ok(Some(FaultMode::Unavailable))
        );
        assert_eq!(plan.take_due(operation, transition), Ok(None));
    }
    assert_eq!(plan.remaining(), 0);
}

#[test]
fn same_target_operations_cannot_consume_each_others_faults() {
    let plan = FaultPlan::new([
        (
            FaultOperation::ResultsFinalization,
            DurableTransition::RunFinalized,
            FaultMode::IndeterminateMutation,
        ),
        (
            FaultOperation::ResultsRead,
            DurableTransition::ResultsPublished,
            FaultMode::CorruptResponse,
        ),
        (
            FaultOperation::ObjectWrite,
            DurableTransition::LeaseCommitted,
            FaultMode::Unavailable,
        ),
    ])
    .expect("fault plan");

    assert_eq!(
        plan.take_due(FaultOperation::ResultsRead, DurableTransition::RunFinalized)
            .expect_err("read is armed later")
            .expected(),
        DurableTransition::ResultsPublished
    );
    assert_eq!(
        plan.take_due(
            FaultOperation::ResultsMutation,
            DurableTransition::RunFinalized
        ),
        Ok(None)
    );
    assert_eq!(
        plan.take_due(
            FaultOperation::ObjectRead,
            DurableTransition::LeaseCommitted
        ),
        Ok(None)
    );
    assert_eq!(plan.remaining(), 3);
    assert_eq!(
        plan.take_due(
            FaultOperation::ResultsFinalization,
            DurableTransition::RunFinalized
        ),
        Ok(Some(FaultMode::IndeterminateMutation))
    );
    assert_eq!(
        plan.take_due(
            FaultOperation::ObjectWrite,
            DurableTransition::LeaseCommitted
        ),
        Ok(Some(FaultMode::Unavailable))
    );
    assert_eq!(plan.remaining(), 1);
}

#[test]
fn fault_plan_rejects_modes_that_cannot_be_represented_by_the_operation() {
    for (operation, mode) in [
        (
            FaultOperation::ResultsRead,
            FaultMode::IndeterminateMutation,
        ),
        (FaultOperation::ObjectRead, FaultMode::IndeterminateMutation),
        (FaultOperation::RunnerSync, FaultMode::CredentialRejected),
        (
            FaultOperation::ChecksCredential,
            FaultMode::RateLimited {
                retry_after_millis: 1,
            },
        ),
    ] {
        assert!(matches!(
            FaultPlan::new([(operation, DurableTransition::Provisioned, mode)]),
            Err(FixtureControlError::InvalidFault)
        ));
    }
    for operation in [
        FaultOperation::ObjectWrite,
        FaultOperation::ResultsMutation,
        FaultOperation::ResultsFinalization,
    ] {
        FaultPlan::new([(
            operation,
            DurableTransition::Provisioned,
            FaultMode::IndeterminateMutation,
        )])
        .expect("mutating ports support an after-commit indeterminate result");
    }
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
    let fixture_clock: Arc<dyn ConformanceClock> = clock.clone();
    let control =
        FixtureControl::for_shard(fixture_clock, Arc::new(FaultPlan::default()), &plan, 0)
            .expect("control from derived shard");
    assert_eq!(
        control.transition(DurableTransition::WebhookAccepted),
        Err(FixtureControlError::RestartRequired)
    );
    assert_eq!(
        control.restart_with(ProductService::Runner, &FakeRestartProbe::running()),
        Err(FixtureControlError::UnexpectedRestartService)
    );
    assert_eq!(
        control.transition(DurableTransition::WorkflowAdmitted),
        Err(FixtureControlError::NonContiguousTransition)
    );

    let probe = FakeRestartProbe::running();
    let schedule = [
        (
            DurableTransition::Provisioned,
            ProductService::Ingress,
            DurableTransition::WebhookAccepted,
        ),
        (
            DurableTransition::WebhookAccepted,
            ProductService::DeliveryWorker,
            DurableTransition::DeliverySelected,
        ),
        (
            DurableTransition::DeliverySelected,
            ProductService::WorkflowService,
            DurableTransition::WorkflowAdmitted,
        ),
        (
            DurableTransition::WorkflowAdmitted,
            ProductService::Scheduler,
            DurableTransition::JobQueued,
        ),
        (
            DurableTransition::JobQueued,
            ProductService::ControlPlane,
            DurableTransition::LeaseCommitted,
        ),
        (
            DurableTransition::LeaseCommitted,
            ProductService::Runner,
            DurableTransition::JobResultCommitted,
        ),
        (
            DurableTransition::JobResultCommitted,
            ProductService::ControlPlane,
            DurableTransition::RunFinalized,
        ),
        (
            DurableTransition::RunFinalized,
            ProductService::Results,
            DurableTransition::ResultsPublished,
        ),
        (
            DurableTransition::ResultsPublished,
            ProductService::ChecksPublisher,
            DurableTransition::CheckPublished,
        ),
        (
            DurableTransition::CheckPublished,
            ProductService::ObjectStorage,
            DurableTransition::CleanupVerified,
        ),
    ];
    for (current, service, next) in schedule {
        assert_eq!(control.current_transition(), current);
        assert_eq!(current.required_restart_services(), &[service]);
        control
            .restart_with(service, &probe)
            .expect("verified scheduled restart");
        assert_eq!(
            control.restart_with(service, &probe),
            Err(FixtureControlError::DuplicateRestart)
        );
        control.transition(next).expect("next transition");
    }
    assert_eq!(
        control.current_transition(),
        DurableTransition::CleanupVerified
    );
    let records = control.restart_records();
    assert_eq!(records.len(), schedule.len());
    assert_eq!(records[0].stopped_generation(), 7);
    assert_eq!(records[0].started_generation(), 8);
    assert_eq!(records[0].stopped_instance(), "process-7");
    assert_eq!(records[0].started_instance(), "process-8");
    assert!(
        DurableTransition::CleanupVerified
            .required_restart_services()
            .is_empty()
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
        control.restart_with(ProductService::Ingress, &LyingRestartProbe),
        Err(FixtureControlError::RestartDidNotStop)
    );
    assert!(control.restart_records().is_empty());
    assert_eq!(
        control.transition(DurableTransition::WebhookAccepted),
        Err(FixtureControlError::RestartRequired)
    );
    control
        .restart_with(ProductService::Ingress, &FakeRestartProbe::running())
        .expect("failed restart cleared its reservation");
}

#[test]
fn restart_probe_can_inspect_control_without_a_fixture_lock_deadlock() {
    let plan = ShardPlan::derive("reentrant-probe-run", 1).expect("plan");
    let control = Arc::new(
        FixtureControl::for_shard(
            Arc::new(ManualConformanceClock::new(0)),
            Arc::new(FaultPlan::default()),
            &plan,
            0,
        )
        .expect("control"),
    );
    let probe = ReentrantObservationProbe {
        control: Arc::clone(&control),
        inner: FakeRestartProbe::running(),
    };

    control
        .restart_with(ProductService::Ingress, &probe)
        .expect("external callbacks run outside fixture lock");
    assert_eq!(control.restart_records().len(), 1);
}
