use std::sync::{Arc, Mutex};

use automata_ci::app::conformance_control::{
    InjectedProductFault, ProductBoundaryCallError, ProductConformanceAdapterError,
    ProductConformanceAdapters, ProductConformanceClock, ProductFaultOperation,
};
use automata_ci::server::MaintenanceClock;
use automata_ci_auth::time::Clock as AuthClock;
use automata_ci_conformance::{
    DurableTransition, FaultMode, FaultPlan, FaultTarget, FixtureControlError, ProductService,
    ServiceObservation, ServiceRestartProbe, ServiceState, ShardPlan,
};
use automata_ci_control::LeaseClock;
use automata_ci_credential_github::{
    GithubRuntimeAuthorityCoordinatorClock, GithubServerServiceCoordinatorClock,
};
use automata_ci_github_delivery::{GithubDeliveryClock, GithubScheduleClock};
use automata_ci_results_github::ResultsClock;
use automata_ci_workflow_service::AdmissionClock;

#[derive(Debug)]
struct Probe(Mutex<(ServiceState, u64)>);

impl Probe {
    fn new() -> Self {
        Self(Mutex::new((ServiceState::Running, 1)))
    }
}

impl ServiceRestartProbe for Probe {
    fn observe(&self, _service: ProductService) -> Result<ServiceObservation, FixtureControlError> {
        let state = self
            .0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        ServiceObservation::new(state.0, state.1, format!("process-{}", state.1))
    }

    fn stop(&self, _service: ProductService) -> Result<(), FixtureControlError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        state.0 = ServiceState::Stopped;
        Ok(())
    }

    fn start(&self, _service: ProductService) -> Result<(), FixtureControlError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        state.1 += 1;
        state.0 = ServiceState::Running;
        Ok(())
    }
}

fn advance(adapters: &ProductConformanceAdapters, probe: &Probe, next: DurableTransition) {
    let current = adapters.control().current_transition();
    let [service] = current.required_restart_services() else {
        panic!("every nonterminal fixture checkpoint has one scheduled restart");
    };
    adapters
        .control()
        .restart_with(*service, probe)
        .expect("observed restart");
    adapters
        .control()
        .transition(next)
        .expect("contiguous durable transition");
}

const SCRIPTED_FAULTS: [(ProductFaultOperation, DurableTransition); 6] = [
    (
        ProductFaultOperation::SourceFetch,
        DurableTransition::DeliverySelected,
    ),
    (
        ProductFaultOperation::TokenIssue,
        DurableTransition::DeliverySelected,
    ),
    (
        ProductFaultOperation::RunnerSync,
        DurableTransition::JobQueued,
    ),
    (
        ProductFaultOperation::ObjectWrite,
        DurableTransition::LeaseCommitted,
    ),
    (
        ProductFaultOperation::ResultsFinalization,
        DurableTransition::RunFinalized,
    ),
    (
        ProductFaultOperation::ChecksCredential,
        DurableTransition::ResultsPublished,
    ),
];

#[test]
fn one_manual_clock_drives_all_product_time_ports() {
    let clock = ProductConformanceClock::new(12_345).expect("clock");
    assert_eq!(AuthClock::now(&clock).as_seconds(), 12);
    assert_eq!(AdmissionClock::now(&clock).get(), 12_345);
    assert_eq!(GithubDeliveryClock::now(&clock).get(), 12_345);
    assert_eq!(
        GithubScheduleClock::now(&clock).expect("schedule").get(),
        12_345
    );
    assert_eq!(
        GithubRuntimeAuthorityCoordinatorClock::now(&clock).get(),
        12_345
    );
    assert_eq!(
        GithubServerServiceCoordinatorClock::now(&clock).get(),
        12_345
    );
    assert_eq!(ResultsClock::now_seconds(&clock), 12);
    assert_eq!(LeaseClock::now(&clock).get(), 12_345);
    assert_eq!(MaintenanceClock::now(&clock).get(), 12_345);

    clock.advance(655).expect("advance");
    assert_eq!(AdmissionClock::now(&clock).get(), 13_000);
    assert_eq!(ResultsClock::now_seconds(&clock), 13);
    assert!(matches!(
        ProductConformanceClock::new(-1),
        Err(ProductConformanceAdapterError::InvalidInitialTime)
    ));
}

#[tokio::test]
async fn fixture_gate_fails_each_operation_at_its_exact_durable_transition() {
    let faults = Arc::new(
        FaultPlan::new(
            SCRIPTED_FAULTS
                .into_iter()
                .map(|(operation, transition)| (operation, transition, FaultMode::Unavailable)),
        )
        .expect("fault plan"),
    );
    let shards = ShardPlan::derive("product-fault-adapter", 1).expect("shards");
    let adapters =
        ProductConformanceAdapters::for_shard(1_000, faults, &shards, 0).expect("adapters");
    assert_eq!(
        adapters.control().shard(),
        adapters.shard().identity(),
        "control and provisioning must consume one selected identity"
    );
    let probe = Probe::new();
    let operation_calls = Arc::new(Mutex::new(Vec::new()));

    advance(&adapters, &probe, DurableTransition::WebhookAccepted);
    advance(&adapters, &probe, DurableTransition::DeliverySelected);
    for operation in [
        ProductFaultOperation::SourceFetch,
        ProductFaultOperation::TokenIssue,
    ] {
        inject(&adapters, &operation_calls, operation).await;
    }

    advance(&adapters, &probe, DurableTransition::WorkflowAdmitted);
    advance(&adapters, &probe, DurableTransition::JobQueued);
    inject(
        &adapters,
        &operation_calls,
        ProductFaultOperation::RunnerSync,
    )
    .await;
    advance(&adapters, &probe, DurableTransition::LeaseCommitted);
    inject(
        &adapters,
        &operation_calls,
        ProductFaultOperation::ObjectWrite,
    )
    .await;
    advance(&adapters, &probe, DurableTransition::JobResultCommitted);
    advance(&adapters, &probe, DurableTransition::RunFinalized);
    inject(
        &adapters,
        &operation_calls,
        ProductFaultOperation::ResultsFinalization,
    )
    .await;
    advance(&adapters, &probe, DurableTransition::ResultsPublished);
    inject(
        &adapters,
        &operation_calls,
        ProductFaultOperation::ChecksCredential,
    )
    .await;

    assert!(operation_calls.lock().expect("calls").is_empty());
    let events = adapters.faults().events().expect("events");
    assert_eq!(events.len(), SCRIPTED_FAULTS.len());
    assert_eq!(
        events
            .iter()
            .map(InjectedProductFault::operation)
            .collect::<Vec<_>>(),
        SCRIPTED_FAULTS
            .into_iter()
            .map(|(operation, _)| operation)
            .collect::<Vec<_>>()
    );
    assert!(
        events
            .windows(2)
            .all(|pair| pair[0].at_millis() < pair[1].at_millis())
    );
    assert_eq!(adapters.control().faults().remaining(), 0);
}

async fn inject(
    adapters: &ProductConformanceAdapters,
    operation_calls: &Arc<Mutex<Vec<ProductFaultOperation>>>,
    operation: ProductFaultOperation,
) {
    adapters.clock().advance(1).expect("time");
    let calls = Arc::clone(operation_calls);
    let failure = adapters
        .faults()
        .call_async(operation, || async move {
            calls.lock().expect("calls").push(operation);
            Ok::<_, ()>(())
        })
        .await
        .expect_err("scripted failure");
    assert!(matches!(
        failure,
        ProductBoundaryCallError::Injected(ref fault)
            if fault.operation() == operation
                && fault.transition() == adapters.control().current_transition()
                && fault.mode() == &FaultMode::Unavailable
    ));
}

#[test]
fn wrong_transition_does_not_consume_or_invoke_and_real_errors_stay_distinct() {
    let faults = Arc::new(
        FaultPlan::new([(
            ProductFaultOperation::RunnerSync,
            DurableTransition::JobQueued,
            FaultMode::Unavailable,
        )])
        .expect("fault plan"),
    );
    let shards = ShardPlan::derive("wrong-transition", 1).expect("shards");
    let adapters = ProductConformanceAdapters::for_shard(0, faults, &shards, 0).expect("adapters");
    let error = adapters
        .faults()
        .call(ProductFaultOperation::RunnerSync, || {
            Ok::<_, &'static str>(())
        })
        .expect_err("wrong transition");
    assert!(matches!(
        error,
        ProductBoundaryCallError::Adapter(ProductConformanceAdapterError::WrongFaultTransition {
            operation: ProductFaultOperation::RunnerSync,
            expected: DurableTransition::JobQueued,
            actual: DurableTransition::Provisioned,
        })
    ));
    assert_eq!(adapters.control().faults().remaining(), 1);
    assert!(adapters.faults().events().expect("events").is_empty());
    let probe = Probe::new();
    advance(&adapters, &probe, DurableTransition::WebhookAccepted);
    advance(&adapters, &probe, DurableTransition::DeliverySelected);
    advance(&adapters, &probe, DurableTransition::WorkflowAdmitted);
    advance(&adapters, &probe, DurableTransition::JobQueued);
    assert!(matches!(
        adapters
            .faults()
            .call(ProductFaultOperation::RunnerSync, || Ok::<_, &'static str>(())),
        Err(ProductBoundaryCallError::Injected(ref fault))
            if fault.target() == FaultTarget::Runner
    ));
    assert_eq!(adapters.control().faults().remaining(), 0);
    assert_eq!(
        adapters
            .faults()
            .call(ProductFaultOperation::RunnerSync, || {
                Ok::<_, &'static str>("retry ran")
            }),
        Ok("retry ran")
    );
    advance(&adapters, &probe, DurableTransition::LeaseCommitted);
    assert_eq!(
        adapters
            .faults()
            .call(ProductFaultOperation::RunnerSync, || {
                Ok::<_, &'static str>("exhausted plan delegates at another stage")
            }),
        Ok("exhausted plan delegates at another stage")
    );

    let empty = Arc::new(FaultPlan::default());
    let adapters = ProductConformanceAdapters::for_shard(0, empty, &shards, 0).expect("adapters");
    assert_eq!(
        adapters
            .faults()
            .call(ProductFaultOperation::SourceFetch, || {
                Err::<(), _>("real source error")
            }),
        Err(ProductBoundaryCallError::Operation("real source error"))
    );
}
