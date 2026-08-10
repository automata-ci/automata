use std::future::pending;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use automata_ci::{
    build_info::BuildInfo,
    server::{
        ControlPlaneMetrics, ManagedService, ManagedServiceError, ServiceSupervisorError,
        supervise_services, supervise_services_with_metrics,
        supervise_services_with_metrics_and_provider,
    },
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

async fn fake_service(
    cancellation: CancellationToken,
    entered: Arc<AtomicUsize>,
    drained: Arc<AtomicUsize>,
) -> Result<(), ManagedServiceError> {
    entered.fetch_add(1, Ordering::AcqRel);
    cancellation.cancelled().await;
    drained.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

async fn failing_drain_service(
    cancellation: CancellationToken,
    entered: Arc<AtomicUsize>,
    drained: Arc<AtomicUsize>,
    error: ManagedServiceError,
) -> Result<(), ManagedServiceError> {
    entered.fetch_add(1, Ordering::AcqRel);
    cancellation.cancelled().await;
    drained.fetch_add(1, Ordering::AcqRel);
    Err(error)
}

#[tokio::test]
async fn one_shutdown_signal_drains_every_managed_service() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let supervisor = supervise_services(
        (
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
            fake_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
            ),
        ),
        async move {
            let _ = shutdown_rx.await;
        },
        cancellation,
    );
    let task = tokio::spawn(supervisor);

    while entered.load(Ordering::Acquire) != 8 {
        tokio::task::yield_now().await;
    }
    shutdown_tx
        .send(())
        .expect("supervisor must await shutdown");

    task.await
        .expect("supervisor task must join")
        .expect("graceful shutdown must succeed");
    assert_eq!(drained.load(Ordering::Acquire), 8);
}

#[tokio::test]
async fn one_shutdown_signal_drains_the_metrics_listener_with_every_sibling() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let services = (
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
        fake_service(
            cancellation.child_token(),
            Arc::clone(&entered),
            Arc::clone(&drained),
        ),
    );
    let supervisor = supervise_services_with_metrics(
        services,
        async move {
            let _ = shutdown_rx.await;
        },
        cancellation,
        metrics.clone(),
    );
    let task = tokio::spawn(supervisor);

    while entered.load(Ordering::Acquire) != 9 {
        tokio::task::yield_now().await;
    }
    shutdown_tx.send(()).expect("supervisor awaits shutdown");
    task.await
        .expect("supervisor task joins")
        .expect("graceful shutdown succeeds");
    assert_eq!(drained.load(Ordering::Acquire), 9);

    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    for service in [
        "human_http",
        "runner_control",
        "results_http",
        "metrics_http",
        "readiness_monitor",
        "control_plane_maintenance",
        "logical_run_finalization",
        "logical_result_projection",
        "autonomous_workflow",
    ] {
        assert!(exposition.contains(&format!(
            "automata_ci_control_plane_supervised_service_exits_total{{service=\"{service}\",outcome=\"graceful\"}} 1"
        )));
    }
}

#[tokio::test]
async fn configured_provider_is_a_tenth_gracefully_drained_service() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let service = |cancellation: CancellationToken| {
        fake_service(cancellation, Arc::clone(&entered), Arc::clone(&drained))
    };
    let supervisor = supervise_services_with_metrics_and_provider(
        (
            service(cancellation.child_token()),
            service(cancellation.child_token()),
            service(cancellation.child_token()),
            service(cancellation.child_token()),
            service(cancellation.child_token()),
            service(cancellation.child_token()),
            service(cancellation.child_token()),
            service(cancellation.child_token()),
            service(cancellation.child_token()),
            service(cancellation.child_token()),
        ),
        pending(),
        async move {
            let _ = shutdown_rx.await;
        },
        cancellation,
        metrics.clone(),
    );
    let task = tokio::spawn(supervisor);

    while entered.load(Ordering::Acquire) != 10 {
        tokio::task::yield_now().await;
    }
    shutdown_tx.send(()).expect("supervisor awaits shutdown");
    task.await
        .expect("supervisor task joins")
        .expect("graceful shutdown succeeds");
    assert_eq!(drained.load(Ordering::Acquire), 10);
    assert!(metrics.exporter().encode_openmetrics().expect("metrics").as_str().contains(
        "automata_ci_control_plane_supervised_service_exits_total{service=\"github_provider\",outcome=\"graceful\"} 1"
    ));
}

#[tokio::test]
async fn an_unexpected_provider_stop_is_fatal_and_cancels_every_sibling() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let sibling = |cancellation: CancellationToken| {
        fake_service(cancellation, Arc::clone(&entered), Arc::clone(&drained))
    };

    let result = supervise_services_with_metrics_and_provider(
        (
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            async { Ok(()) },
        ),
        pending(),
        pending(),
        cancellation,
        metrics.clone(),
    )
    .await;
    assert_eq!(
        result,
        Err(ServiceSupervisorError::UnexpectedStop(
            ManagedService::GithubProvider
        ))
    );
    assert_eq!(entered.load(Ordering::Acquire), 9);
    assert_eq!(drained.load(Ordering::Acquire), 9);
    assert!(metrics.exporter().encode_openmetrics().expect("metrics").as_str().contains(
        "automata_ci_control_plane_supervised_service_exits_total{service=\"github_provider\",outcome=\"unexpected_stop\"} 1"
    ));
}

#[tokio::test]
async fn provider_fatal_signal_cancels_then_awaits_drain_and_wins_classification() {
    let cancellation = CancellationToken::new();
    let observed_cancellation = cancellation.clone();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let provider_entered = Arc::new(AtomicUsize::new(0));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let sibling = |cancellation: CancellationToken| {
        fake_service(cancellation, Arc::clone(&entered), Arc::clone(&drained))
    };
    let (fatal_tx, fatal_rx) = oneshot::channel();
    let (provider_release_tx, provider_release_rx) = oneshot::channel();
    let provider_entered_task = provider_entered.clone();

    let supervisor = supervise_services_with_metrics_and_provider(
        (
            failing_drain_service(
                cancellation.child_token(),
                Arc::clone(&entered),
                Arc::clone(&drained),
                ManagedServiceError::HumanHttp,
            ),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            async move {
                provider_entered_task.fetch_add(1, Ordering::AcqRel);
                let _ = provider_release_rx.await;
                Err(ManagedServiceError::GithubProvider)
            },
        ),
        async move {
            fatal_rx.await.expect("provider fatal notification");
        },
        pending(),
        cancellation,
        metrics.clone(),
    );
    let task = tokio::spawn(supervisor);
    tokio::time::timeout(Duration::from_secs(1), async {
        while entered.load(Ordering::Acquire) != 9 || provider_entered.load(Ordering::Acquire) != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all managed futures must start");

    fatal_tx.send(()).expect("fatal notifier remains awaited");
    tokio::time::timeout(Duration::from_secs(1), async {
        while drained.load(Ordering::Acquire) != 9 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fatal notification must cancel and drain every sibling");
    assert!(observed_cancellation.is_cancelled());
    assert!(
        !task.is_finished(),
        "provider custody must remain supervised until its drain completes"
    );

    provider_release_tx
        .send(())
        .expect("provider drain remains owned");
    assert_eq!(
        task.await.expect("supervisor task joins"),
        Err(ServiceSupervisorError::Service(
            ManagedServiceError::GithubProvider
        )),
        "the provider signal must outrank a sibling failure during drain"
    );

    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    let exposition = exposition.as_str();
    for (outcome, value) in [("failure", 1), ("graceful", 0), ("unexpected_stop", 0)] {
        assert!(exposition.contains(&format!(
            "automata_ci_control_plane_supervised_service_exits_total{{service=\"github_provider\",outcome=\"{outcome}\"}} {value}"
        )));
    }
}

#[tokio::test]
async fn an_unexpected_metrics_listener_stop_is_fatal_and_cancels_siblings() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let sibling = |cancellation: CancellationToken| {
        fake_service(cancellation, Arc::clone(&entered), Arc::clone(&drained))
    };

    let result = supervise_services_with_metrics(
        (
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            async { Ok(()) },
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
        ),
        pending(),
        cancellation,
        metrics.clone(),
    )
    .await;
    assert_eq!(
        result,
        Err(ServiceSupervisorError::UnexpectedStop(
            ManagedService::MetricsHttp
        ))
    );
    assert_eq!(entered.load(Ordering::Acquire), 8);
    assert_eq!(drained.load(Ordering::Acquire), 8);

    let exposition = metrics
        .exporter()
        .encode_openmetrics()
        .expect("bounded exposition");
    assert!(exposition.as_str().contains(
        "automata_ci_control_plane_supervised_service_exits_total{service=\"metrics_http\",outcome=\"unexpected_stop\"} 1"
    ));
}

#[tokio::test]
async fn an_unexpected_finalization_stop_is_fatal_and_cancels_every_sibling() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let sibling = |cancellation: CancellationToken| {
        fake_service(cancellation, Arc::clone(&entered), Arc::clone(&drained))
    };

    let result = supervise_services_with_metrics(
        (
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            async { Ok(()) },
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
        ),
        pending(),
        cancellation,
        metrics.clone(),
    )
    .await;
    assert_eq!(
        result,
        Err(ServiceSupervisorError::UnexpectedStop(
            ManagedService::LogicalRunFinalization
        ))
    );
    assert_eq!(entered.load(Ordering::Acquire), 8);
    assert_eq!(drained.load(Ordering::Acquire), 8);
    assert!(metrics.exporter().encode_openmetrics().expect("metrics").as_str().contains(
        "automata_ci_control_plane_supervised_service_exits_total{service=\"logical_run_finalization\",outcome=\"unexpected_stop\"} 1"
    ));
}

#[tokio::test]
async fn an_unexpected_result_projection_stop_is_fatal_and_cancels_every_sibling() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let sibling = |cancellation: CancellationToken| {
        fake_service(cancellation, Arc::clone(&entered), Arc::clone(&drained))
    };

    let result = supervise_services_with_metrics(
        (
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            async { Ok(()) },
            sibling(cancellation.child_token()),
        ),
        pending(),
        cancellation,
        metrics.clone(),
    )
    .await;
    assert_eq!(
        result,
        Err(ServiceSupervisorError::UnexpectedStop(
            ManagedService::LogicalResultProjection
        ))
    );
    assert_eq!(entered.load(Ordering::Acquire), 8);
    assert_eq!(drained.load(Ordering::Acquire), 8);
    assert!(metrics.exporter().encode_openmetrics().expect("metrics").as_str().contains(
        "automata_ci_control_plane_supervised_service_exits_total{service=\"logical_result_projection\",outcome=\"unexpected_stop\"} 1"
    ));
}

#[tokio::test]
async fn an_unexpected_autonomous_workflow_stop_is_fatal_and_cancels_every_sibling() {
    let cancellation = CancellationToken::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let drained = Arc::new(AtomicUsize::new(0));
    let metrics = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
    let sibling = |cancellation: CancellationToken| {
        fake_service(cancellation, Arc::clone(&entered), Arc::clone(&drained))
    };

    let result = supervise_services_with_metrics(
        (
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            sibling(cancellation.child_token()),
            async { Ok(()) },
        ),
        pending(),
        cancellation,
        metrics.clone(),
    )
    .await;
    assert_eq!(
        result,
        Err(ServiceSupervisorError::UnexpectedStop(
            ManagedService::AutonomousWorkflow
        ))
    );
    assert_eq!(entered.load(Ordering::Acquire), 8);
    assert_eq!(drained.load(Ordering::Acquire), 8);
    assert!(metrics.exporter().encode_openmetrics().expect("metrics").as_str().contains(
        "automata_ci_control_plane_supervised_service_exits_total{service=\"autonomous_workflow\",outcome=\"unexpected_stop\"} 1"
    ));
}
