mod support;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use automata_ci_core::{ContainerPort, ContainerSpec, TransportProtocol, ValueSource};
use automata_ci_execution::{ServiceHealthPolicy, ServiceTransportProtocol};
use automata_ci_runner_runtime::{
    CleanupRequest, ExecutionCancellation, ExecutionEvents, JobExecutor,
};

use support::{Fixture, PhaseResponse, envelope_with_services, journal_identity, run_step};

fn immutable_image(name: &str, byte: char) -> String {
    format!(
        "registry.example/{name}@sha256:{}",
        byte.to_string().repeat(64)
    )
}

fn service_job(service: ContainerSpec) -> automata_ci_core::JobIrEnvelope {
    envelope_with_services(
        vec![run_step("probe", "Probe service", "true")],
        BTreeMap::from([("database".to_owned(), service)]),
    )
}

#[tokio::test]
async fn service_specs_cross_the_fenced_sandbox_boundary_and_cleanup_with_the_job() {
    let service = ContainerSpec::new(immutable_image("database", 'd'))
        .with_environment(BTreeMap::from([
            (
                "POSTGRES_DB".to_owned(),
                ValueSource::Literal("ci".to_owned()),
            ),
            (
                "POSTGRES_PASSWORD".to_owned(),
                ValueSource::SecretReference("test-token".to_owned()),
            ),
        ]))
        .with_ports([ContainerPort::new(
            5432,
            Some(15432),
            TransportProtocol::Tcp,
        )])
        .with_options([
            "--health-cmd=pg_isready".to_owned(),
            "--health-interval".to_owned(),
            "10s".to_owned(),
            "--health-timeout=5s".to_owned(),
            "--health-retries=5".to_owned(),
        ]);
    let fixture = Fixture::new(Vec::new(), Vec::new());
    let job = service_job(service);
    fixture.executor.admit(&job).expect("service job admitted");
    let request = fixture.request(job);
    let session_id = request.session_id();
    let slot = request.slot();
    let attempt_id = request.lease().attempt_id();
    let guard = request.lease().guard();
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events.clone(), ExecutionCancellation::new())
        .await
        .expect("service job executes");
    assert_eq!(
        result.conclusion(),
        automata_ci_core::JobConclusion::Success
    );

    let specs = fixture.provider.specs();
    let sandbox = specs.last().expect("sandbox create spec");
    let database = sandbox
        .services()
        .get("database")
        .expect("database service");
    assert_eq!(
        database.image().reference(),
        immutable_image("database", 'd')
    );
    assert_eq!(database.ports().len(), 1);
    assert_eq!(database.ports()[0].container_port(), 5432);
    assert_eq!(database.ports()[0].requested_host_port(), Some(15432));
    assert_eq!(
        database.ports()[0].protocol(),
        ServiceTransportProtocol::Tcp
    );
    let environment = database
        .environment()
        .values()
        .iter()
        .map(|variable| (variable.name().as_str(), variable.value().expose()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(environment["POSTGRES_DB"], "ci");
    assert_eq!(environment["POSTGRES_PASSWORD"], support::SECRET);
    assert!(
        database
            .environment()
            .values()
            .iter()
            .find(|variable| variable.name().as_str() == "POSTGRES_PASSWORD")
            .expect("resolved service secret")
            .is_secret()
    );
    let ServiceHealthPolicy::Override(health) = database.health() else {
        panic!("health override");
    };
    assert_eq!(health.command(), Some("pg_isready"));
    assert_eq!(health.interval(), Some(Duration::from_secs(10)));
    assert_eq!(health.timeout(), Some(Duration::from_secs(5)));
    assert_eq!(health.retries(), Some(5));
    assert!(!format!("{sandbox:?}").contains(support::SECRET));
    assert!(!format!("{sandbox:?}").contains("pg_isready"));

    let cleanup = CleanupRequest::new(session_id, slot, attempt_id, guard, journal_identity());
    fixture
        .executor
        .cleanup(cleanup, events, ExecutionCancellation::new())
        .await
        .expect("sandbox and services are destroyed together");
    assert_eq!(fixture.provider.counts(), (1, 1, 1));
}

#[tokio::test]
async fn cancelled_service_job_retains_exact_sandbox_cleanup_ownership() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success().cancelled()]);
    let job = service_job(ContainerSpec::new(immutable_image("database", 'c')));
    let request = fixture.request(job);
    let session_id = request.session_id();
    let slot = request.slot();
    let attempt_id = request.lease().attempt_id();
    let guard = request.lease().guard();
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events.clone(), ExecutionCancellation::new())
        .await
        .expect("cancellation is a terminal job result");
    assert_eq!(
        result.conclusion(),
        automata_ci_core::JobConclusion::Cancelled
    );
    assert_eq!(fixture.events.sandbox(), Some(journal_identity()));

    fixture
        .executor
        .cleanup(
            CleanupRequest::new(session_id, slot, attempt_id, guard, journal_identity()),
            events,
            ExecutionCancellation::new(),
        )
        .await
        .expect("cancelled job cleanup destroys services with the sandbox");
    assert_eq!(fixture.provider.counts(), (1, 1, 1));
}

#[test]
fn unsupported_or_nondurable_service_surface_fails_closed_at_admission() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    for service in [
        ContainerSpec::new("postgres:latest"),
        ContainerSpec::new(immutable_image("database", 'e'))
            .with_options(["--privileged".to_owned()]),
        ContainerSpec::new(immutable_image("database", 'f')).with_ports([ContainerPort::new(
            0,
            None,
            TransportProtocol::Tcp,
        )]),
    ] {
        assert!(fixture.executor.admit(&service_job(service)).is_err());
    }

    let unsupported_provider = Fixture::without_service_containers(Vec::new(), Vec::new());
    let exact_service = ContainerSpec::new(immutable_image("database", 'a'));
    assert!(
        unsupported_provider
            .executor
            .admit(&service_job(exact_service))
            .is_err()
    );
}
