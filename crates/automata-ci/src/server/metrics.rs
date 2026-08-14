use std::{
    fmt,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, Instant, SystemTime},
};

use automata_ci_control::{
    LeaseClaimRejection, LeasePollFailure, LeasePollObservation, LeasePollObserver,
};
use automata_ci_metrics::{
    BuildInfo as MetricsBuildInfo, BuildInfoError, Counter, ExporterLimits, Family, Gauge,
    Histogram, Metrics, MetricsBuilder, ProcessMetricsSampler, ProcessRole, Registry, Unit,
    classic_and_native_histogram,
};
use automata_ci_results_github::{
    ResultsBlobOperation, ResultsBlobOperationOutcome, ResultsHttpMethod, ResultsHttpRoute,
    ResultsHttpStatusClass, ResultsObserver, ResultsOperation, ResultsOperationOutcome,
    ResultsRepositoryOperation, ResultsRepositoryOperationOutcome, ResultsTransferDirection,
};
use automata_ci_runner_control::{
    LeaseOfferObservation, RunnerControlFailure, RunnerControlMessageKind,
    RunnerControlMessageOutcome, RunnerControlObserver, RunnerDurableDisposition,
    RunnerDurableMessageKind, RunnerHandshakeOutcome, RunnerHandshakeRejection,
    RunnerLeaseRequestStage,
};
use automata_ci_runner_transport::{
    RunnerTransportApplicationRejection, RunnerTransportAuthenticationRejection,
    RunnerTransportBodyRejection, RunnerTransportByteDirection, RunnerTransportConnectionEvent,
    RunnerTransportDecodeRejection, RunnerTransportHeadRejection, RunnerTransportObserver,
    RunnerTransportRequestObservation, RunnerTransportResponseRejection, RunnerTransportRoute,
    RunnerTransportTlsOutcome,
};
use automata_ci_store::ControlPlaneStateRepository;
use automata_ci_workflow_service::{
    WorkflowAdmissionFailure, WorkflowAdmissionObservation, WorkflowAdmissionObserver,
    WorkflowAdmissionStage, WorkflowAdmissionStageOutcome,
};
use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use prometheus_client::encoding::EncodeLabelSet;

use crate::{
    app::{
        delegated_actor_api::DELEGATED_ACTOR_VIEWER_PATH,
        github_auth::{
            CLI_SESSION_PATH, GITHUB_DEVICE_BEGIN_PATH, GITHUB_DEVICE_POLL_PATH,
            GITHUB_SETUP_DEVICE_BEGIN_PATH, GITHUB_SETUP_DEVICE_POLL_PATH,
            GITHUB_SETUP_WEB_BEGIN_PATH, GITHUB_WEB_BEGIN_PATH, GITHUB_WEB_CALLBACK_PATH,
            GITHUB_WEB_LOGOUT_PATH,
        },
        management_api::{
            DIRECT_BINDING_PATH, DIRECT_BINDINGS_PATH, ROLE_PATH, ROLE_PERMISSION_PATH, ROLES_PATH,
            USER_PATH, USERS_PATH,
        },
        protected_environment_review_api::PROTECTED_ENVIRONMENT_REVIEW_PATH,
        repository_secrets::{
            REPOSITORY_SECRET_DELETE_PATH, REPOSITORY_SECRET_PROVIDER_ACTIVATE_PATH,
            REPOSITORY_SECRET_REPLACE_PATH, REPOSITORY_SECRETS_SETTINGS_PATH,
        },
        runner_enrollment_api::{RUNNER_ENROLLMENT_REDEEM_PATH, RUNNER_ENROLLMENTS_PATH},
        secret_api::{
            BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH, BUILTIN_SECRET_PROVIDER_PATH,
            GITHUB_REPOSITORY_SECRET_RESOLUTION_PATH, REPOSITORY_SECRET_BY_NAME_PATH,
            REPOSITORY_SECRET_PATH, REPOSITORY_SECRETS_PATH,
        },
        shard_capabilities::SHARD_CAPABILITIES_PATH,
        workflow_rerun_api::WORKFLOW_RERUN_PATH,
    },
    build_info::BuildInfo,
};

use super::{
    github_webhook::GITHUB_WEBHOOK_PATH,
    state_metrics::{ControlPlaneStateMetrics, ControlPlaneStateSampler},
};

const HTTP_DURATION_BUCKETS_SECONDS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
const DEPENDENCY_DURATION_BUCKETS_SECONDS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 30.0,
];
const MAINTENANCE_DURATION_BUCKETS_SECONDS: [f64; 10] =
    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0];
const CONTROL_DURATION_BUCKETS_SECONDS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
const RESULTS_DURATION_BUCKETS_SECONDS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
const CANDIDATE_BUCKETS: [f64; 9] = [0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0];
const QUEUE_WAIT_BUCKETS_SECONDS: [f64; 10] = [
    1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1_800.0, 3_600.0,
];
const HTTP_METHOD_LABELS: [&str; 8] = [
    "get", "head", "post", "put", "patch", "delete", "options", "other",
];
const RBAC_SETTINGS_ROUTE: &str = "/settings/access/{rbac}";
const GITHUB_DEVICE_ROUTE: &str = "/api/v1/auth/device/{operation}";
const REPOSITORY_SECRET_BROWSER_MUTATION_ROUTE: &str =
    "/{owner}/{repository}/settings/secrets/{mutation}";
const HTTP_ROUTE_LABELS: [&str; 45] = [
    "/healthz",
    "/readyz",
    SHARD_CAPABILITIES_PATH,
    DELEGATED_ACTOR_VIEWER_PATH,
    "/",
    "/setup",
    "/repositories",
    "/{owner}/{repository}/actions",
    "/{owner}/{repository}/actions/workflows/{workflow_id}",
    "/{owner}/{repository}/actions/runs/{run_id}",
    "/{owner}/{repository}/actions/runs/{run_id}/jobs/{job_id}",
    "/{owner}/{repository}/actions/runs/{run_id}/artifacts/{artifact_id}",
    "/{owner}/{repository}/settings/access",
    REPOSITORY_SECRETS_SETTINGS_PATH,
    REPOSITORY_SECRET_BROWSER_MUTATION_ROUTE,
    RBAC_SETTINGS_ROUTE,
    "/assets/{*asset_path}",
    GITHUB_WEBHOOK_PATH,
    GITHUB_WEB_BEGIN_PATH,
    GITHUB_WEB_CALLBACK_PATH,
    GITHUB_WEB_LOGOUT_PATH,
    GITHUB_DEVICE_ROUTE,
    CLI_SESSION_PATH,
    GITHUB_SETUP_WEB_BEGIN_PATH,
    GITHUB_SETUP_DEVICE_BEGIN_PATH,
    GITHUB_SETUP_DEVICE_POLL_PATH,
    USERS_PATH,
    USER_PATH,
    ROLES_PATH,
    ROLE_PATH,
    ROLE_PERMISSION_PATH,
    DIRECT_BINDINGS_PATH,
    DIRECT_BINDING_PATH,
    PROTECTED_ENVIRONMENT_REVIEW_PATH,
    WORKFLOW_RERUN_PATH,
    GITHUB_REPOSITORY_SECRET_RESOLUTION_PATH,
    REPOSITORY_SECRETS_PATH,
    REPOSITORY_SECRET_PATH,
    REPOSITORY_SECRET_BY_NAME_PATH,
    BUILTIN_SECRET_PROVIDER_PATH,
    BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH,
    RUNNER_ENROLLMENTS_PATH,
    RUNNER_ENROLLMENT_REDEEM_PATH,
    "other",
    "unmatched",
];
const HTTP_STATUS_CLASS_LABELS: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

type TimestampGauge = Gauge<f64, AtomicU64>;

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct DependencyLabels {
    dependency: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct DependencyProbeLabels {
    dependency: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct DependencyTransitionLabels {
    dependency: &'static str,
    state: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct MaintenancePassLabels {
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct MaintenanceWorkLabels {
    kind: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ServiceLabels {
    service: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct HttpRequestLabels {
    method: &'static str,
    route: &'static str,
    status_class: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct HttpRouteLabels {
    route: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ResultsOperationLabels {
    operation: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ResultsOperationDurationLabels {
    operation: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ResultsDirectionLabels {
    direction: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct StorageOperationLabels {
    backend: &'static str,
    operation: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct StorageOperationDurationLabels {
    backend: &'static str,
    operation: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct StorageByteLabels {
    backend: &'static str,
    direction: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ResultsHttpRequestLabels {
    method: &'static str,
    route: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct ResultsHttpRouteLabels {
    route: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct LeasePollLabels {
    outcome: &'static str,
    disposition: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct OutcomeLabels {
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct AdmissionStageLabels {
    stage: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct AdmissionStageDurationLabels {
    stage: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RunnerControlMessageLabels {
    kind: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RunnerControlKindLabels {
    kind: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RunnerTransportRequestLabels {
    route: &'static str,
    stage: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RunnerTransportRouteStageLabels {
    route: &'static str,
    stage: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RunnerTransportRouteLabels {
    route: &'static str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, EncodeLabelSet)]
struct RunnerTransportByteLabels {
    route: &'static str,
    direction: &'static str,
}

#[derive(Clone)]
struct ResultsMetrics {
    operations: Family<ResultsOperationLabels, Counter>,
    operation_duration: Family<ResultsOperationDurationLabels, Histogram>,
    transfer_bytes: Family<ResultsDirectionLabels, Counter>,
    storage_operations: Family<StorageOperationLabels, Counter>,
    storage_operation_duration: Family<StorageOperationDurationLabels, Histogram>,
    storage_bytes: Family<StorageByteLabels, Counter>,
    http_requests: Family<ResultsHttpRequestLabels, Counter>,
    http_request_duration: Family<ResultsHttpRouteLabels, Histogram>,
    http_in_flight: Family<ResultsHttpRouteLabels, Gauge>,
}

impl ResultsMetrics {
    fn register(registry: &mut Registry) -> Self {
        let metrics = Self {
            operations: Family::default(),
            operation_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(RESULTS_DURATION_BUCKETS_SECONDS)
            }),
            transfer_bytes: Family::default(),
            storage_operations: Family::default(),
            storage_operation_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(RESULTS_DURATION_BUCKETS_SECONDS)
            }),
            storage_bytes: Family::default(),
            http_requests: Family::default(),
            http_request_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(RESULTS_DURATION_BUCKETS_SECONDS)
            }),
            http_in_flight: Family::default(),
        };
        registry.register(
            "results_operations",
            "Physical Results application operations by fixed operation and terminal outcome.",
            metrics.operations.clone(),
        );
        registry.register_with_unit(
            "results_operation_duration",
            "Results application operation duration by fixed operation.",
            Unit::Seconds,
            metrics.operation_duration.clone(),
        );
        registry.register_with_unit(
            "results",
            "Artifact payload bytes accepted from uploads or yielded to downloads.",
            Unit::Bytes,
            metrics.transfer_bytes.clone(),
        );
        registry.register(
            "storage_operations",
            "Physical Results storage operations by fixed backend, operation, and outcome.",
            metrics.storage_operations.clone(),
        );
        registry.register_with_unit(
            "storage_operation_duration",
            "Results storage operation duration by fixed backend and operation.",
            Unit::Seconds,
            metrics.storage_operation_duration.clone(),
        );
        registry.register_with_unit(
            "storage",
            "Bytes accepted or returned by the Results immutable object-store boundary.",
            Unit::Bytes,
            metrics.storage_bytes.clone(),
        );
        registry.register(
            "results_http_requests",
            "Results-listener requests by fixed method, matched route, and response or cancellation outcome.",
            metrics.http_requests.clone(),
        );
        registry.register_with_unit(
            "results_http_request_duration",
            "Results-listener request duration by fixed matched route, including cancellations.",
            Unit::Seconds,
            metrics.http_request_duration.clone(),
        );
        registry.register(
            "results_http_requests_in_flight",
            "Results-listener requests currently in flight by fixed matched route.",
            metrics.http_in_flight.clone(),
        );
        metrics.preinitialize();
        metrics
    }

    fn preinitialize(&self) {
        for operation in results_operations() {
            let _ = self
                .operation_duration
                .get_or_create(&ResultsOperationDurationLabels { operation });
            for outcome in results_operation_outcomes() {
                let _ = self
                    .operations
                    .get_or_create(&ResultsOperationLabels { operation, outcome });
            }
        }
        for direction in ["upload", "download"] {
            let _ = self
                .transfer_bytes
                .get_or_create(&ResultsDirectionLabels { direction });
        }

        for operation in repository_operations() {
            let _ =
                self.storage_operation_duration
                    .get_or_create(&StorageOperationDurationLabels {
                        backend: "postgresql",
                        operation,
                    });
            for outcome in repository_operation_outcomes() {
                let _ = self
                    .storage_operations
                    .get_or_create(&StorageOperationLabels {
                        backend: "postgresql",
                        operation,
                        outcome,
                    });
            }
        }
        for operation in ["put", "get"] {
            let _ =
                self.storage_operation_duration
                    .get_or_create(&StorageOperationDurationLabels {
                        backend: "object_store",
                        operation,
                    });
        }
        for outcome in blob_put_outcomes() {
            let _ = self
                .storage_operations
                .get_or_create(&StorageOperationLabels {
                    backend: "object_store",
                    operation: "put",
                    outcome,
                });
        }
        for outcome in blob_get_outcomes() {
            let _ = self
                .storage_operations
                .get_or_create(&StorageOperationLabels {
                    backend: "object_store",
                    operation: "get",
                    outcome,
                });
        }
        for direction in ["write", "read"] {
            let _ = self.storage_bytes.get_or_create(&StorageByteLabels {
                backend: "object_store",
                direction,
            });
        }

        for route in results_http_routes() {
            let labels = ResultsHttpRouteLabels { route };
            let _ = self.http_request_duration.get_or_create(&labels);
            self.http_in_flight.get_or_create(&labels).set(0);
            for method in ["get", "post", "put", "other"] {
                for outcome in ["1xx", "2xx", "3xx", "4xx", "5xx", "cancelled"] {
                    let _ = self.http_requests.get_or_create(&ResultsHttpRequestLabels {
                        method,
                        route,
                        outcome,
                    });
                }
            }
        }
    }
}

#[derive(Clone)]
struct ControlSemanticMetrics {
    lease_polls: Family<LeasePollLabels, Counter>,
    lease_poll_duration: Family<OutcomeLabels, Histogram>,
    lease_candidates: Histogram,
    lease_queue_wait: Histogram,
    workflow_admissions: Family<OutcomeLabels, Counter>,
    workflow_admission_duration: Family<OutcomeLabels, Histogram>,
    workflow_stages: Family<AdmissionStageLabels, Counter>,
    workflow_stage_duration: Family<AdmissionStageDurationLabels, Histogram>,
    workflow_jobs_committed: Counter,
    workflow_receipt_replays: Counter,
    runner_handshakes: Family<OutcomeLabels, Counter>,
    runner_handshake_duration: Family<OutcomeLabels, Histogram>,
    runner_messages: Family<RunnerControlMessageLabels, Counter>,
    runner_message_duration: Family<RunnerControlKindLabels, Histogram>,
    runner_durable_transitions: Family<RunnerControlKindLabels, Counter>,
    runner_receipt_replays: Family<RunnerControlKindLabels, Counter>,
    runner_ingress_bytes: Family<RunnerControlKindLabels, Counter>,
    runner_lease_offers: Family<OutcomeLabels, Counter>,
    runner_transport_connections: Family<OutcomeLabels, Counter>,
    runner_transport_tls: Family<OutcomeLabels, Counter>,
    runner_transport_tls_duration: Family<OutcomeLabels, Histogram>,
    runner_transport_requests: Family<RunnerTransportRequestLabels, Counter>,
    runner_transport_request_duration: Family<RunnerTransportRouteStageLabels, Histogram>,
    runner_transport_in_flight: Family<RunnerTransportRouteLabels, Gauge>,
    runner_transport_bytes: Family<RunnerTransportByteLabels, Counter>,
}

impl ControlSemanticMetrics {
    #[allow(clippy::too_many_lines)] // One declarative registration keeps the semantic schema auditable.
    fn register(registry: &mut Registry) -> Self {
        let metrics = Self {
            lease_polls: Family::default(),
            lease_poll_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(CONTROL_DURATION_BUCKETS_SECONDS)
            }),
            lease_candidates: classic_and_native_histogram(CANDIDATE_BUCKETS),
            lease_queue_wait: classic_and_native_histogram(QUEUE_WAIT_BUCKETS_SECONDS),
            workflow_admissions: Family::default(),
            workflow_admission_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(CONTROL_DURATION_BUCKETS_SECONDS)
            }),
            workflow_stages: Family::default(),
            workflow_stage_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(CONTROL_DURATION_BUCKETS_SECONDS)
            }),
            workflow_jobs_committed: Counter::default(),
            workflow_receipt_replays: Counter::default(),
            runner_handshakes: Family::default(),
            runner_handshake_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(CONTROL_DURATION_BUCKETS_SECONDS)
            }),
            runner_messages: Family::default(),
            runner_message_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(CONTROL_DURATION_BUCKETS_SECONDS)
            }),
            runner_durable_transitions: Family::default(),
            runner_receipt_replays: Family::default(),
            runner_ingress_bytes: Family::default(),
            runner_lease_offers: Family::default(),
            runner_transport_connections: Family::default(),
            runner_transport_tls: Family::default(),
            runner_transport_tls_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(CONTROL_DURATION_BUCKETS_SECONDS)
            }),
            runner_transport_requests: Family::default(),
            runner_transport_request_duration: Family::new_with_constructor(|| {
                classic_and_native_histogram(CONTROL_DURATION_BUCKETS_SECONDS)
            }),
            runner_transport_in_flight: Family::default(),
            runner_transport_bytes: Family::default(),
        };
        registry.register(
            "control_plane_lease_polls",
            "Physical lease polls by closed semantic outcome, durable disposition, and reason.",
            metrics.lease_polls.clone(),
        );
        registry.register_with_unit(
            "control_plane_lease_poll_duration",
            "Physical lease-poll duration by closed outcome.",
            Unit::Seconds,
            metrics.lease_poll_duration.clone(),
        );
        registry.register(
            "control_plane_lease_poll_candidates",
            "Runnable candidates inspected by each fresh lease poll.",
            metrics.lease_candidates.clone(),
        );
        registry.register_with_unit(
            "control_plane_lease_queue_wait",
            "Durable queue-to-claim latency for newly committed claims.",
            Unit::Seconds,
            metrics.lease_queue_wait.clone(),
        );
        registry.register(
            "control_plane_workflow_admissions",
            "Physical workflow admissions by closed final outcome.",
            metrics.workflow_admissions.clone(),
        );
        registry.register_with_unit(
            "control_plane_workflow_admission_duration",
            "Workflow admission duration by closed final outcome.",
            Unit::Seconds,
            metrics.workflow_admission_duration.clone(),
        );
        registry.register(
            "control_plane_workflow_admission_stages",
            "Workflow admission stage executions by fixed stage and outcome.",
            metrics.workflow_stages.clone(),
        );
        registry.register_with_unit(
            "control_plane_workflow_admission_stage_duration",
            "Workflow admission stage duration by fixed stage.",
            Unit::Seconds,
            metrics.workflow_stage_duration.clone(),
        );
        registry.register(
            "control_plane_workflow_jobs_committed",
            "Jobs committed by newly durable workflow admissions; replays are excluded.",
            metrics.workflow_jobs_committed.clone(),
        );
        registry.register(
            "control_plane_workflow_admission_receipt_replays",
            "Workflow admission requests served from prior durable receipts.",
            metrics.workflow_receipt_replays.clone(),
        );
        registry.register(
            "control_plane_runner_control_handshakes",
            "Runner-control server handshake attempts by closed semantic outcome.",
            metrics.runner_handshakes.clone(),
        );
        registry.register_with_unit(
            "control_plane_runner_control_handshake_duration",
            "Runner-control server handshake duration by closed semantic outcome.",
            Unit::Seconds,
            metrics.runner_handshake_duration.clone(),
        );
        registry.register(
            "control_plane_runner_control_messages",
            "Physical runner-control server messages by fixed kind and semantic outcome.",
            metrics.runner_messages.clone(),
        );
        registry.register_with_unit(
            "control_plane_runner_control_message_duration",
            "Runner-control server message duration by fixed kind.",
            Unit::Seconds,
            metrics.runner_message_duration.clone(),
        );
        registry.register(
            "control_plane_runner_control_durable_transitions",
            "Newly committed runner-control semantic transitions by fixed kind.",
            metrics.runner_durable_transitions.clone(),
        );
        registry.register(
            "control_plane_runner_control_receipt_replays",
            "Runner-control semantic operations served from prior durable receipts.",
            metrics.runner_receipt_replays.clone(),
        );
        registry.register_with_unit(
            "control_plane_runner_control_ingress",
            "Newly committed canonical result and uncompressed log payload bytes.",
            Unit::Bytes,
            metrics.runner_ingress_bytes.clone(),
        );
        registry.register(
            "control_plane_runner_control_lease_offer_events",
            "Lease-offer publication and recovery events by closed outcome.",
            metrics.runner_lease_offers.clone(),
        );
        registry.register(
            "control_plane_runner_transport_connection_events",
            "Physical runner-control connection admission and terminal events by closed outcome.",
            metrics.runner_transport_connections.clone(),
        );
        registry.register(
            "control_plane_runner_transport_tls_handshakes",
            "Runner-control TLS and peer-evidence admissions by closed outcome.",
            metrics.runner_transport_tls.clone(),
        );
        registry.register_with_unit(
            "control_plane_runner_transport_tls_handshake_duration",
            "Runner-control TLS and peer-evidence admission duration by closed outcome.",
            Unit::Seconds,
            metrics.runner_transport_tls_duration.clone(),
        );
        registry.register(
            "control_plane_runner_transport_requests",
            "Physical runner-control HTTP/2 requests by fixed route and terminal stage/outcome.",
            metrics.runner_transport_requests.clone(),
        );
        registry.register_with_unit(
            "control_plane_runner_transport_request_duration",
            "Physical runner-control request duration through its terminal processing stage.",
            Unit::Seconds,
            metrics.runner_transport_request_duration.clone(),
        );
        registry.register(
            "control_plane_runner_transport_requests_in_flight",
            "Route-validated runner-control requests currently in flight.",
            metrics.runner_transport_in_flight.clone(),
        );
        registry.register_with_unit(
            "control_plane_runner_transport",
            "Completely collected runner-control request and successful response body bytes.",
            Unit::Bytes,
            metrics.runner_transport_bytes.clone(),
        );
        metrics.preinitialize();
        metrics
    }

    #[allow(clippy::too_many_lines)] // Closed reachable tuples remain visible in one reviewable schema walk.
    fn preinitialize(&self) {
        for (outcome, disposition, reason) in lease_poll_label_values() {
            let _ = self.lease_polls.get_or_create(&LeasePollLabels {
                outcome,
                disposition,
                reason,
            });
        }
        for outcome in ["claimed", "no_work", "rejected", "error"] {
            let _ = self
                .lease_poll_duration
                .get_or_create(&OutcomeLabels { outcome });
        }
        for outcome in workflow_outcomes() {
            let labels = OutcomeLabels { outcome };
            let _ = self.workflow_admissions.get_or_create(&labels);
            let _ = self.workflow_admission_duration.get_or_create(&labels);
        }
        for stage in workflow_stages() {
            let _ = self
                .workflow_stage_duration
                .get_or_create(&AdmissionStageDurationLabels { stage });
            for outcome in ["success", "failure"] {
                let _ = self
                    .workflow_stages
                    .get_or_create(&AdmissionStageLabels { stage, outcome });
            }
        }
        for outcome in handshake_outcomes() {
            let labels = OutcomeLabels { outcome };
            let _ = self.runner_handshakes.get_or_create(&labels);
            let _ = self.runner_handshake_duration.get_or_create(&labels);
        }
        for kind in runner_message_kinds() {
            let kind_labels = RunnerControlKindLabels { kind };
            let _ = self.runner_message_duration.get_or_create(&kind_labels);
            // This remaining product is production-reachable: common stale-fence conversion,
            // authorization/session loading, and pending-command recovery apply to every kind.
            // In particular, a pending command can make JobState succeed, while pending
            // lease-offer validation can make it conflict before its unsupported response.
            for outcome in runner_message_outcomes() {
                let _ = self
                    .runner_messages
                    .get_or_create(&RunnerControlMessageLabels { kind, outcome });
            }
        }
        for kind in runner_durable_kinds() {
            let labels = RunnerControlKindLabels { kind };
            let _ = self.runner_durable_transitions.get_or_create(&labels);
            let _ = self.runner_receipt_replays.get_or_create(&labels);
            let _ = self.runner_ingress_bytes.get_or_create(&labels);
        }
        for outcome in ["published", "replay", "superseded", "failed"] {
            let _ = self
                .runner_lease_offers
                .get_or_create(&OutcomeLabels { outcome });
        }
        for outcome in [
            "admitted",
            "overloaded",
            "http2_closed",
            "http2_error",
            "shutdown",
            "drain_aborted",
            "lifetime_expired",
        ] {
            let _ = self
                .runner_transport_connections
                .get_or_create(&OutcomeLabels { outcome });
        }
        for outcome in [
            "accepted",
            "timeout",
            "rejected",
            "invalid_protocol",
            "invalid_peer_identity",
        ] {
            let labels = OutcomeLabels { outcome };
            let _ = self.runner_transport_tls.get_or_create(&labels);
            let _ = self.runner_transport_tls_duration.get_or_create(&labels);
        }

        self.preinitialize_transport_request("unknown", "admission", "overloaded");
        self.preinitialize_transport_request("unknown", "cancelled", "cancelled");
        for outcome in ["http_version", "method", "not_found"] {
            self.preinitialize_transport_request("unknown", "head", outcome);
        }
        for route in ["handshake", "sync"] {
            self.preinitialize_transport_request(route, "cancelled", "cancelled");
            for (stage, outcomes) in [
                (
                    "head",
                    &[
                        "unsupported_media_type",
                        "length_required",
                        "invalid_content_length",
                        "body_too_large",
                    ][..],
                ),
                (
                    "authentication",
                    &["untrusted", "expired", "unavailable", "timeout"][..],
                ),
                (
                    "body",
                    &["too_large", "invalid", "transport", "timeout"][..],
                ),
                (
                    "decode",
                    &["invalid_protobuf", "route_mismatch", "canonicalization"][..],
                ),
                (
                    "application",
                    &[
                        "forbidden",
                        "conflict",
                        "unavailable",
                        "internal",
                        "timeout",
                    ][..],
                ),
                (
                    "response",
                    &["invalid_correlation", "encoding", "too_large", "success"][..],
                ),
            ] {
                for outcome in outcomes {
                    self.preinitialize_transport_request(route, stage, outcome);
                }
            }
            self.runner_transport_in_flight
                .get_or_create(&RunnerTransportRouteLabels { route })
                .set(0);
            for direction in ["request", "response"] {
                let _ = self
                    .runner_transport_bytes
                    .get_or_create(&RunnerTransportByteLabels { route, direction });
            }
        }
        let route = "ephemeral_secrets";
        self.preinitialize_transport_request(route, "cancelled", "cancelled");
        for (stage, outcomes) in [
            (
                "head",
                &[
                    "http_version",
                    "method",
                    "not_found",
                    "unsupported_media_type",
                    "length_required",
                    "invalid_content_length",
                    "body_too_large",
                ][..],
            ),
            (
                "authentication",
                &["untrusted", "expired", "unavailable", "timeout"][..],
            ),
            (
                "body",
                &["too_large", "invalid", "transport", "timeout"][..],
            ),
            (
                "application",
                &[
                    "forbidden",
                    "conflict",
                    "unavailable",
                    "internal",
                    "timeout",
                ][..],
            ),
            ("response", &["too_large", "success"][..]),
        ] {
            for outcome in outcomes {
                self.preinitialize_transport_request(route, stage, outcome);
            }
        }
        self.runner_transport_in_flight
            .get_or_create(&RunnerTransportRouteLabels { route })
            .set(0);
        for direction in ["request", "response"] {
            let _ = self
                .runner_transport_bytes
                .get_or_create(&RunnerTransportByteLabels { route, direction });
        }
    }

    fn preinitialize_transport_request(
        &self,
        route: &'static str,
        stage: &'static str,
        outcome: &'static str,
    ) {
        let _ = self
            .runner_transport_requests
            .get_or_create(&RunnerTransportRequestLabels {
                route,
                stage,
                outcome,
            });
        let _ = self
            .runner_transport_request_duration
            .get_or_create(&RunnerTransportRouteStageLabels { route, stage });
    }
}

/// One control-plane process's typed handles into the shared metrics registry.
///
/// Every label value is selected from the closed mappings below. Request paths,
/// dependency errors, durable identities, and provider details never reach the
/// registry.
#[derive(Clone)]
pub struct ControlPlaneMetrics {
    exporter: Metrics,
    process_sampler: ProcessMetricsSampler,
    ready: Gauge,
    dependency_ready: Family<DependencyLabels, Gauge>,
    dependency_probes: Family<DependencyProbeLabels, Counter>,
    dependency_probe_duration: Family<DependencyLabels, Histogram>,
    dependency_last_success: Family<DependencyLabels, TimestampGauge>,
    dependency_transitions: Family<DependencyTransitionLabels, Counter>,
    maintenance_passes: Family<MaintenancePassLabels, Counter>,
    maintenance_pass_duration: Family<MaintenancePassLabels, Histogram>,
    maintenance_work: Family<MaintenanceWorkLabels, Counter>,
    maintenance_last_success: TimestampGauge,
    maintenance_batch_saturated: Gauge,
    service_exits: Family<ServiceLabels, Counter>,
    http_requests: Family<HttpRequestLabels, Counter>,
    http_request_duration: Family<HttpRouteLabels, Histogram>,
    http_in_flight: Family<HttpRouteLabels, Gauge>,
    semantics: ControlSemanticMetrics,
    results: ResultsMetrics,
    state: ControlPlaneStateMetrics,
}

impl ControlPlaneMetrics {
    /// Registers the fixed control-plane schema in the process's sole registry.
    ///
    /// # Errors
    ///
    /// Returns a sanitized foundation error if common metric registration fails.
    pub fn new(build: BuildInfo) -> Result<Self, BuildInfoError> {
        let mut builder = MetricsBuilder::new(MetricsBuildInfo::new(
            ProcessRole::ControlPlane,
            build.version,
            build.commit,
        ))?;

        let ready = Gauge::default();
        let dependency_ready = Family::<DependencyLabels, Gauge>::default();
        let dependency_probes = Family::<DependencyProbeLabels, Counter>::default();
        let dependency_probe_duration =
            Family::<DependencyLabels, Histogram>::new_with_constructor(|| {
                classic_and_native_histogram(DEPENDENCY_DURATION_BUCKETS_SECONDS)
            });
        let dependency_last_success = Family::<DependencyLabels, TimestampGauge>::default();
        let dependency_transitions = Family::<DependencyTransitionLabels, Counter>::default();
        let maintenance_passes = Family::<MaintenancePassLabels, Counter>::default();
        let maintenance_pass_duration =
            Family::<MaintenancePassLabels, Histogram>::new_with_constructor(|| {
                classic_and_native_histogram(MAINTENANCE_DURATION_BUCKETS_SECONDS)
            });
        let maintenance_work = Family::<MaintenanceWorkLabels, Counter>::default();
        let maintenance_last_success = TimestampGauge::default();
        let maintenance_batch_saturated = Gauge::default();
        let service_exits = Family::<ServiceLabels, Counter>::default();
        let http_requests = Family::<HttpRequestLabels, Counter>::default();
        let http_request_duration =
            Family::<HttpRouteLabels, Histogram>::new_with_constructor(|| {
                classic_and_native_histogram(HTTP_DURATION_BUCKETS_SECONDS)
            });
        let http_in_flight = Family::<HttpRouteLabels, Gauge>::default();

        register_readiness_metrics(
            builder.registry_mut(),
            &ready,
            &dependency_ready,
            &dependency_probes,
            &dependency_probe_duration,
            &dependency_last_success,
            &dependency_transitions,
        );
        register_maintenance_metrics(
            builder.registry_mut(),
            &maintenance_passes,
            &maintenance_pass_duration,
            &maintenance_work,
            &maintenance_last_success,
            &maintenance_batch_saturated,
        );
        register_runtime_metrics(
            builder.registry_mut(),
            &service_exits,
            &http_requests,
            &http_request_duration,
            &http_in_flight,
        );
        let semantics = ControlSemanticMetrics::register(builder.registry_mut());
        let results = ResultsMetrics::register(builder.registry_mut());
        let state = ControlPlaneStateMetrics::register(builder.registry_mut());

        let process_sampler = builder.process_sampler();
        let exporter = builder.finish(ExporterLimits::default());
        let metrics = Self {
            exporter,
            process_sampler,
            ready,
            dependency_ready,
            dependency_probes,
            dependency_probe_duration,
            dependency_last_success,
            dependency_transitions,
            maintenance_passes,
            maintenance_pass_duration,
            maintenance_work,
            maintenance_last_success,
            maintenance_batch_saturated,
            service_exits,
            http_requests,
            http_request_duration,
            http_in_flight,
            semantics,
            results,
            state,
        };
        metrics.preinitialize();
        Ok(metrics)
    }

    /// Returns the shared exporter for the dedicated operations listener.
    #[must_use]
    pub const fn exporter(&self) -> &Metrics {
        &self.exporter
    }

    pub(crate) fn process_sampler(&self) -> ProcessMetricsSampler {
        self.process_sampler.clone()
    }

    pub(crate) fn state_sampler(
        &self,
        source: Arc<dyn ControlPlaneStateRepository>,
    ) -> ControlPlaneStateSampler {
        self.state.sampler(source)
    }

    fn preinitialize(&self) {
        for dependency in ["database", "object_store"] {
            let dependency_labels = DependencyLabels { dependency };
            self.dependency_ready
                .get_or_create(&dependency_labels)
                .set(0);
            let _ = self
                .dependency_probe_duration
                .get_or_create(&dependency_labels);
            self.dependency_last_success
                .get_or_create(&dependency_labels)
                .set(0.0);
            for outcome in ["success", "error", "timeout"] {
                let _ = self
                    .dependency_probes
                    .get_or_create(&DependencyProbeLabels {
                        dependency,
                        outcome,
                    });
            }
            for state in ["ready", "unready"] {
                let _ = self
                    .dependency_transitions
                    .get_or_create(&DependencyTransitionLabels { dependency, state });
            }
        }
        for outcome in ["success", "error", "cancelled", "invalid_observation"] {
            let labels = MaintenancePassLabels { outcome };
            let _ = self.maintenance_passes.get_or_create(&labels);
            let _ = self.maintenance_pass_duration.get_or_create(&labels);
        }
        for kind in [
            "requeued_attempt",
            "lost_attempt",
            "skipped_blocked_attempt",
            "closed_stale_session",
        ] {
            let _ = self
                .maintenance_work
                .get_or_create(&MaintenanceWorkLabels { kind });
        }
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
            "github_provider",
        ] {
            for outcome in ["graceful", "failure", "unexpected_stop"] {
                let _ = self
                    .service_exits
                    .get_or_create(&ServiceLabels { service, outcome });
            }
        }
        for route in HTTP_ROUTE_LABELS {
            let labels = HttpRouteLabels { route };
            let _ = self.http_request_duration.get_or_create(&labels);
            self.http_in_flight.get_or_create(&labels).set(0);
            for method in HTTP_METHOD_LABELS {
                for status_class in HTTP_STATUS_CLASS_LABELS {
                    let _ = self.http_requests.get_or_create(&HttpRequestLabels {
                        method,
                        route,
                        status_class,
                    });
                }
            }
        }
    }

    pub(crate) fn observe_dependency_probe(
        &self,
        dependency: &'static str,
        outcome: &'static str,
        duration: Duration,
        previous_ready: bool,
        current_ready: bool,
    ) {
        self.dependency_probes
            .get_or_create(&DependencyProbeLabels {
                dependency,
                outcome,
            })
            .inc();
        self.dependency_probe_duration
            .get_or_create(&DependencyLabels { dependency })
            .observe(duration.as_secs_f64());
        self.dependency_ready
            .get_or_create(&DependencyLabels { dependency })
            .set(i64::from(current_ready));
        if outcome == "success" {
            self.dependency_last_success
                .get_or_create(&DependencyLabels { dependency })
                .set(unix_timestamp_seconds());
        }
        if previous_ready != current_ready {
            self.dependency_transitions
                .get_or_create(&DependencyTransitionLabels {
                    dependency,
                    state: if current_ready { "ready" } else { "unready" },
                })
                .inc();
        }
    }

    pub(crate) fn set_ready(&self, ready: bool) {
        self.ready.set(i64::from(ready));
    }

    pub(crate) fn observe_maintenance_pass(&self, outcome: &'static str, duration: Duration) {
        let labels = MaintenancePassLabels { outcome };
        self.maintenance_passes.get_or_create(&labels).inc();
        self.maintenance_pass_duration
            .get_or_create(&labels)
            .observe(duration.as_secs_f64());
    }

    pub(crate) fn observe_maintenance_success(
        &self,
        duration: Duration,
        requeued: usize,
        lost: usize,
        skipped_blocked: u16,
        closed_stale_sessions: u16,
        saturated: bool,
    ) {
        self.observe_maintenance_pass("success", duration);
        for (kind, count) in [
            (
                "requeued_attempt",
                u64::try_from(requeued).unwrap_or(u64::MAX),
            ),
            ("lost_attempt", u64::try_from(lost).unwrap_or(u64::MAX)),
            ("skipped_blocked_attempt", u64::from(skipped_blocked)),
            ("closed_stale_session", u64::from(closed_stale_sessions)),
        ] {
            self.maintenance_work
                .get_or_create(&MaintenanceWorkLabels { kind })
                .inc_by(count);
        }
        self.maintenance_last_success.set(unix_timestamp_seconds());
        self.maintenance_batch_saturated.set(i64::from(saturated));
    }

    pub(crate) fn observe_service_exit(&self, service: &'static str, outcome: &'static str) {
        self.service_exits
            .get_or_create(&ServiceLabels { service, outcome })
            .inc();
    }

    fn start_http(&self, method: &Method, matched_path: Option<&str>) -> HttpObservation {
        let method = http_method(method);
        let labels = HttpRouteLabels {
            route: http_route(matched_path),
        };
        self.http_in_flight.get_or_create(&labels).inc();
        HttpObservation {
            metrics: self.clone(),
            method,
            labels,
            started: Instant::now(),
            in_flight: true,
        }
    }
}

fn register_readiness_metrics(
    registry: &mut Registry,
    ready: &Gauge,
    dependency_ready: &Family<DependencyLabels, Gauge>,
    dependency_probes: &Family<DependencyProbeLabels, Counter>,
    dependency_probe_duration: &Family<DependencyLabels, Histogram>,
    dependency_last_success: &Family<DependencyLabels, TimestampGauge>,
    dependency_transitions: &Family<DependencyTransitionLabels, Counter>,
) {
    registry.register(
        "control_plane_ready",
        "Whether mandatory control-plane dependencies and workers are ready.",
        ready.clone(),
    );
    registry.register(
        "control_plane_dependency_ready",
        "Whether one mandatory control-plane dependency is ready.",
        dependency_ready.clone(),
    );
    registry.register(
        "control_plane_dependency_probes",
        "Readiness probe attempts by closed dependency and outcome.",
        dependency_probes.clone(),
    );
    registry.register_with_unit(
        "control_plane_dependency_probe_duration",
        "Readiness probe duration in seconds by closed dependency.",
        Unit::Seconds,
        dependency_probe_duration.clone(),
    );
    registry.register_with_unit(
        "control_plane_dependency_last_success_timestamp",
        "Unix timestamp of the last successful dependency readiness probe.",
        Unit::Seconds,
        dependency_last_success.clone(),
    );
    registry.register(
        "control_plane_dependency_readiness_transitions",
        "Dependency readiness state transitions by destination state.",
        dependency_transitions.clone(),
    );
}

fn register_maintenance_metrics(
    registry: &mut Registry,
    maintenance_passes: &Family<MaintenancePassLabels, Counter>,
    maintenance_pass_duration: &Family<MaintenancePassLabels, Histogram>,
    maintenance_work: &Family<MaintenanceWorkLabels, Counter>,
    maintenance_last_success: &TimestampGauge,
    maintenance_batch_saturated: &Gauge,
) {
    registry.register(
        "control_plane_maintenance_passes",
        "Control-plane maintenance passes by closed outcome.",
        maintenance_passes.clone(),
    );
    registry.register_with_unit(
        "control_plane_maintenance_pass_duration",
        "Control-plane maintenance pass duration in seconds by outcome.",
        Unit::Seconds,
        maintenance_pass_duration.clone(),
    );
    registry.register(
        "control_plane_maintenance_work_items",
        "Durable work performed by control-plane maintenance passes.",
        maintenance_work.clone(),
    );
    registry.register_with_unit(
        "control_plane_maintenance_last_success_timestamp",
        "Unix timestamp of the last successful maintenance pass.",
        Unit::Seconds,
        maintenance_last_success.clone(),
    );
    registry.register(
        "control_plane_maintenance_batch_saturated",
        "Whether the latest successful maintenance pass reached a work-category batch limit.",
        maintenance_batch_saturated.clone(),
    );
}

fn register_runtime_metrics(
    registry: &mut Registry,
    service_exits: &Family<ServiceLabels, Counter>,
    http_requests: &Family<HttpRequestLabels, Counter>,
    http_request_duration: &Family<HttpRouteLabels, Histogram>,
    http_in_flight: &Family<HttpRouteLabels, Gauge>,
) {
    registry.register(
        "control_plane_supervised_service_exits",
        "Managed service exits by fixed service and outcome.",
        service_exits.clone(),
    );
    registry.register(
        "control_plane_http_requests",
        "Human HTTP requests by method, matched route template, and status class.",
        http_requests.clone(),
    );
    registry.register_with_unit(
        "control_plane_http_request_duration",
        "Human HTTP request duration in seconds by matched route template.",
        Unit::Seconds,
        http_request_duration.clone(),
    );
    registry.register(
        "control_plane_http_requests_in_flight",
        "Human HTTP requests currently in flight by matched route template.",
        http_in_flight.clone(),
    );
}

impl fmt::Debug for ControlPlaneMetrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPlaneMetrics")
            .finish_non_exhaustive()
    }
}

impl ResultsObserver for ControlPlaneMetrics {
    fn observe_operation(
        &self,
        operation: ResultsOperation,
        outcome: ResultsOperationOutcome,
        duration: Duration,
    ) {
        let operation = results_operation(operation);
        self.results
            .operations
            .get_or_create(&ResultsOperationLabels {
                operation,
                outcome: results_operation_outcome(outcome),
            })
            .inc();
        self.results
            .operation_duration
            .get_or_create(&ResultsOperationDurationLabels { operation })
            .observe(duration.as_secs_f64());
    }

    fn observe_transfer_bytes(&self, direction: ResultsTransferDirection, bytes: u64) {
        self.results
            .transfer_bytes
            .get_or_create(&ResultsDirectionLabels {
                direction: results_transfer_direction(direction),
            })
            .inc_by(bytes);
    }

    fn results_http_request_started(&self, _method: ResultsHttpMethod, route: ResultsHttpRoute) {
        self.results
            .http_in_flight
            .get_or_create(&ResultsHttpRouteLabels {
                route: results_http_route_label(route),
            })
            .inc();
    }

    fn observe_results_http_request(
        &self,
        method: ResultsHttpMethod,
        route: ResultsHttpRoute,
        status: ResultsHttpStatusClass,
        duration: Duration,
    ) {
        let route = results_http_route_label(route);
        self.results
            .http_requests
            .get_or_create(&ResultsHttpRequestLabels {
                method: results_http_method_label(method),
                route,
                outcome: results_http_outcome(status),
            })
            .inc();
        self.results
            .http_request_duration
            .get_or_create(&ResultsHttpRouteLabels { route })
            .observe(duration.as_secs_f64());
    }

    fn results_http_request_finished(&self, _method: ResultsHttpMethod, route: ResultsHttpRoute) {
        self.results
            .http_in_flight
            .get_or_create(&ResultsHttpRouteLabels {
                route: results_http_route_label(route),
            })
            .dec();
    }

    fn observe_blob_operation(
        &self,
        operation: ResultsBlobOperation,
        outcome: ResultsBlobOperationOutcome,
        duration: Duration,
    ) {
        let operation = results_blob_operation(operation);
        self.results
            .storage_operations
            .get_or_create(&StorageOperationLabels {
                backend: "object_store",
                operation,
                outcome: results_blob_outcome(outcome),
            })
            .inc();
        self.results
            .storage_operation_duration
            .get_or_create(&StorageOperationDurationLabels {
                backend: "object_store",
                operation,
            })
            .observe(duration.as_secs_f64());
    }

    fn observe_blob_bytes(&self, operation: ResultsBlobOperation, bytes: u64) {
        self.results
            .storage_bytes
            .get_or_create(&StorageByteLabels {
                backend: "object_store",
                direction: match operation {
                    ResultsBlobOperation::Put => "write",
                    ResultsBlobOperation::Get => "read",
                },
            })
            .inc_by(bytes);
    }

    fn observe_repository_operation(
        &self,
        operation: ResultsRepositoryOperation,
        outcome: ResultsRepositoryOperationOutcome,
        duration: Duration,
    ) {
        let operation = results_repository_operation(operation);
        self.results
            .storage_operations
            .get_or_create(&StorageOperationLabels {
                backend: "postgresql",
                operation,
                outcome: results_repository_outcome(outcome),
            })
            .inc();
        self.results
            .storage_operation_duration
            .get_or_create(&StorageOperationDurationLabels {
                backend: "postgresql",
                operation,
            })
            .observe(duration.as_secs_f64());
    }
}

impl LeasePollObserver for ControlPlaneMetrics {
    fn observe_poll(&self, observation: LeasePollObservation, duration: Duration) {
        let (outcome, disposition, reason) = lease_poll_labels(observation);
        self.semantics
            .lease_polls
            .get_or_create(&LeasePollLabels {
                outcome,
                disposition,
                reason,
            })
            .inc();
        self.semantics
            .lease_poll_duration
            .get_or_create(&OutcomeLabels { outcome })
            .observe(duration.as_secs_f64());
    }

    fn observe_candidates(&self, count: usize) {
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        self.semantics.lease_candidates.observe(f64::from(count));
    }

    fn observe_queue_wait(&self, duration: Duration) {
        self.semantics
            .lease_queue_wait
            .observe(duration.as_secs_f64());
    }
}

impl WorkflowAdmissionObserver for ControlPlaneMetrics {
    fn observe_stage(
        &self,
        stage: WorkflowAdmissionStage,
        outcome: WorkflowAdmissionStageOutcome,
        duration: Duration,
    ) {
        let stage = workflow_stage(stage);
        let outcome = match outcome {
            WorkflowAdmissionStageOutcome::Success => "success",
            WorkflowAdmissionStageOutcome::Failure => "failure",
        };
        self.semantics
            .workflow_stages
            .get_or_create(&AdmissionStageLabels { stage, outcome })
            .inc();
        self.semantics
            .workflow_stage_duration
            .get_or_create(&AdmissionStageDurationLabels { stage })
            .observe(duration.as_secs_f64());
    }

    fn observe_admission(&self, observation: WorkflowAdmissionObservation, duration: Duration) {
        let outcome = workflow_outcome(observation);
        self.semantics
            .workflow_admissions
            .get_or_create(&OutcomeLabels { outcome })
            .inc();
        self.semantics
            .workflow_admission_duration
            .get_or_create(&OutcomeLabels { outcome })
            .observe(duration.as_secs_f64());
        match observation {
            WorkflowAdmissionObservation::New { jobs } => {
                self.semantics
                    .workflow_jobs_committed
                    .inc_by(u64::try_from(jobs).unwrap_or(u64::MAX));
            }
            WorkflowAdmissionObservation::Replay => {
                self.semantics.workflow_receipt_replays.inc();
            }
            WorkflowAdmissionObservation::Failed(_) => {}
        }
    }
}

impl RunnerControlObserver for ControlPlaneMetrics {
    fn observe_handshake(&self, observation: RunnerHandshakeOutcome, duration: Duration) {
        let outcome = runner_handshake_outcome(observation);
        let labels = OutcomeLabels { outcome };
        self.semantics
            .runner_handshakes
            .get_or_create(&labels)
            .inc();
        self.semantics
            .runner_handshake_duration
            .get_or_create(&labels)
            .observe(duration.as_secs_f64());
    }

    fn observe_message(
        &self,
        kind: RunnerControlMessageKind,
        outcome: RunnerControlMessageOutcome,
        duration: Duration,
    ) {
        let kind = runner_message_kind(kind);
        let outcome = runner_message_outcome(outcome);
        self.semantics
            .runner_messages
            .get_or_create(&RunnerControlMessageLabels { kind, outcome })
            .inc();
        self.semantics
            .runner_message_duration
            .get_or_create(&RunnerControlKindLabels { kind })
            .observe(duration.as_secs_f64());
    }

    fn observe_durable(
        &self,
        kind: RunnerDurableMessageKind,
        disposition: RunnerDurableDisposition,
        bytes: u64,
    ) {
        let kind = runner_durable_kind(kind);
        let labels = RunnerControlKindLabels { kind };
        match disposition {
            RunnerDurableDisposition::New => {
                self.semantics
                    .runner_durable_transitions
                    .get_or_create(&labels)
                    .inc();
                if bytes > 0 {
                    self.semantics
                        .runner_ingress_bytes
                        .get_or_create(&labels)
                        .inc_by(bytes);
                }
            }
            RunnerDurableDisposition::Replay => {
                self.semantics
                    .runner_receipt_replays
                    .get_or_create(&labels)
                    .inc();
            }
        }
    }

    fn observe_lease_offer(&self, observation: LeaseOfferObservation) {
        let outcome = match observation {
            LeaseOfferObservation::Published => "published",
            LeaseOfferObservation::Replay => "replay",
            LeaseOfferObservation::Superseded => "superseded",
            LeaseOfferObservation::Failed => "failed",
        };
        self.semantics
            .runner_lease_offers
            .get_or_create(&OutcomeLabels { outcome })
            .inc();
    }

    fn observe_lease_request_failure(
        &self,
        stage: RunnerLeaseRequestStage,
        failure: RunnerControlFailure,
    ) {
        tracing::warn!(
            ?stage,
            ?failure,
            "runner lease request failed at application stage"
        );
    }
}

impl RunnerTransportObserver for ControlPlaneMetrics {
    fn observe_connection(&self, event: RunnerTransportConnectionEvent) {
        let outcome = match event {
            RunnerTransportConnectionEvent::Admitted => "admitted",
            RunnerTransportConnectionEvent::Overloaded => "overloaded",
            RunnerTransportConnectionEvent::Http2Closed => "http2_closed",
            RunnerTransportConnectionEvent::Http2Error => "http2_error",
            RunnerTransportConnectionEvent::Shutdown => "shutdown",
            RunnerTransportConnectionEvent::DrainAborted => "drain_aborted",
            RunnerTransportConnectionEvent::LifetimeExpired => "lifetime_expired",
        };
        self.semantics
            .runner_transport_connections
            .get_or_create(&OutcomeLabels { outcome })
            .inc();
    }

    fn observe_tls(&self, outcome: RunnerTransportTlsOutcome, duration: Duration) {
        let outcome = match outcome {
            RunnerTransportTlsOutcome::Accepted => "accepted",
            RunnerTransportTlsOutcome::Timeout => "timeout",
            RunnerTransportTlsOutcome::Rejected => "rejected",
            RunnerTransportTlsOutcome::InvalidProtocol => "invalid_protocol",
            RunnerTransportTlsOutcome::InvalidPeerIdentity => "invalid_peer_identity",
        };
        let labels = OutcomeLabels { outcome };
        self.semantics
            .runner_transport_tls
            .get_or_create(&labels)
            .inc();
        self.semantics
            .runner_transport_tls_duration
            .get_or_create(&labels)
            .observe(duration.as_secs_f64());
    }

    fn observe_request(&self, observation: RunnerTransportRequestObservation, duration: Duration) {
        let (route, stage, outcome) = runner_transport_request_labels(observation);
        self.semantics
            .runner_transport_requests
            .get_or_create(&RunnerTransportRequestLabels {
                route,
                stage,
                outcome,
            })
            .inc();
        self.semantics
            .runner_transport_request_duration
            .get_or_create(&RunnerTransportRouteStageLabels { route, stage })
            .observe(duration.as_secs_f64());
    }

    fn request_started(&self, route: RunnerTransportRoute) {
        self.semantics
            .runner_transport_in_flight
            .get_or_create(&RunnerTransportRouteLabels {
                route: runner_transport_route(route),
            })
            .inc();
    }

    fn request_finished(&self, route: RunnerTransportRoute) {
        self.semantics
            .runner_transport_in_flight
            .get_or_create(&RunnerTransportRouteLabels {
                route: runner_transport_route(route),
            })
            .dec();
    }

    fn observe_bytes(
        &self,
        route: RunnerTransportRoute,
        direction: RunnerTransportByteDirection,
        bytes: u64,
    ) {
        let direction = match direction {
            RunnerTransportByteDirection::Request => "request",
            RunnerTransportByteDirection::Response => "response",
        };
        self.semantics
            .runner_transport_bytes
            .get_or_create(&RunnerTransportByteLabels {
                route: runner_transport_route(route),
                direction,
            })
            .inc_by(bytes);
    }
}

struct HttpObservation {
    metrics: ControlPlaneMetrics,
    method: &'static str,
    labels: HttpRouteLabels,
    started: Instant,
    in_flight: bool,
}

impl HttpObservation {
    fn finish(mut self, status: StatusCode) {
        let duration = self.started.elapsed();
        self.metrics
            .http_requests
            .get_or_create(&HttpRequestLabels {
                method: self.method,
                route: self.labels.route,
                status_class: status_class(status),
            })
            .inc();
        self.metrics
            .http_request_duration
            .get_or_create(&self.labels)
            .observe(duration.as_secs_f64());
        self.metrics
            .http_in_flight
            .get_or_create(&self.labels)
            .dec();
        self.in_flight = false;
    }
}

impl Drop for HttpObservation {
    fn drop(&mut self) {
        if self.in_flight {
            self.metrics
                .http_in_flight
                .get_or_create(&self.labels)
                .dec();
        }
    }
}

pub(crate) async fn observe_http(
    State(metrics): State<ControlPlaneMetrics>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let observation = metrics.start_http(
        request.method(),
        request
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
    );
    let response = next.run(request).await;
    observation.finish(response.status());
    response
}

fn http_method(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "get",
        "HEAD" => "head",
        "POST" => "post",
        "PUT" => "put",
        "PATCH" => "patch",
        "DELETE" => "delete",
        "OPTIONS" => "options",
        _ => "other",
    }
}

fn http_route(matched_path: Option<&str>) -> &'static str {
    match matched_path {
        Some("/healthz") => "/healthz",
        Some("/readyz") => "/readyz",
        Some(SHARD_CAPABILITIES_PATH) => SHARD_CAPABILITIES_PATH,
        Some(DELEGATED_ACTOR_VIEWER_PATH) => DELEGATED_ACTOR_VIEWER_PATH,
        Some("/") => "/",
        Some("/setup") => "/setup",
        Some("/repositories") => "/repositories",
        Some("/{owner}/{repository}/actions") => "/{owner}/{repository}/actions",
        Some("/{owner}/{repository}/actions/workflows/{workflow_id}") => {
            "/{owner}/{repository}/actions/workflows/{workflow_id}"
        }
        Some("/{owner}/{repository}/actions/runs/{run_id}") => {
            "/{owner}/{repository}/actions/runs/{run_id}"
        }
        Some("/{owner}/{repository}/actions/runs/{run_id}/jobs/{job_id}") => {
            "/{owner}/{repository}/actions/runs/{run_id}/jobs/{job_id}"
        }
        Some("/{owner}/{repository}/actions/runs/{run_id}/artifacts/{artifact_id}") => {
            "/{owner}/{repository}/actions/runs/{run_id}/artifacts/{artifact_id}"
        }
        Some("/{owner}/{repository}/settings/access") => "/{owner}/{repository}/settings/access",
        Some(REPOSITORY_SECRETS_SETTINGS_PATH) => REPOSITORY_SECRETS_SETTINGS_PATH,
        Some(
            REPOSITORY_SECRET_REPLACE_PATH
            | REPOSITORY_SECRET_DELETE_PATH
            | REPOSITORY_SECRET_PROVIDER_ACTIVATE_PATH,
        ) => REPOSITORY_SECRET_BROWSER_MUTATION_ROUTE,
        Some(
            "/settings/access/users"
            | "/settings/access/users/{principal_id}"
            | "/settings/access/users/{principal_id}/status"
            | "/settings/access/roles"
            | "/settings/access/roles/{role_id}"
            | "/settings/access/roles/{role_id}/delete"
            | "/settings/access/roles/{role_id}/permissions/{permission}"
            | "/settings/access/direct-bindings"
            | "/settings/access/direct-bindings/{binding_id}/revoke",
        ) => RBAC_SETTINGS_ROUTE,
        Some("/assets/{*asset_path}") => "/assets/{*asset_path}",
        Some(GITHUB_WEB_BEGIN_PATH) => GITHUB_WEB_BEGIN_PATH,
        Some(GITHUB_WEB_CALLBACK_PATH) => GITHUB_WEB_CALLBACK_PATH,
        Some(GITHUB_WEB_LOGOUT_PATH) => GITHUB_WEB_LOGOUT_PATH,
        Some(GITHUB_DEVICE_BEGIN_PATH | GITHUB_DEVICE_POLL_PATH) => GITHUB_DEVICE_ROUTE,
        Some(GITHUB_WEBHOOK_PATH) => GITHUB_WEBHOOK_PATH,
        Some(CLI_SESSION_PATH) => CLI_SESSION_PATH,
        Some(GITHUB_SETUP_WEB_BEGIN_PATH) => GITHUB_SETUP_WEB_BEGIN_PATH,
        Some(GITHUB_SETUP_DEVICE_BEGIN_PATH) => GITHUB_SETUP_DEVICE_BEGIN_PATH,
        Some(GITHUB_SETUP_DEVICE_POLL_PATH) => GITHUB_SETUP_DEVICE_POLL_PATH,
        Some(USERS_PATH) => USERS_PATH,
        Some(USER_PATH) => USER_PATH,
        Some(ROLES_PATH) => ROLES_PATH,
        Some(ROLE_PATH) => ROLE_PATH,
        Some(ROLE_PERMISSION_PATH) => ROLE_PERMISSION_PATH,
        Some(DIRECT_BINDINGS_PATH) => DIRECT_BINDINGS_PATH,
        Some(DIRECT_BINDING_PATH) => DIRECT_BINDING_PATH,
        Some(PROTECTED_ENVIRONMENT_REVIEW_PATH) => PROTECTED_ENVIRONMENT_REVIEW_PATH,
        Some(WORKFLOW_RERUN_PATH) => WORKFLOW_RERUN_PATH,
        Some(GITHUB_REPOSITORY_SECRET_RESOLUTION_PATH) => GITHUB_REPOSITORY_SECRET_RESOLUTION_PATH,
        Some(REPOSITORY_SECRETS_PATH) => REPOSITORY_SECRETS_PATH,
        Some(REPOSITORY_SECRET_PATH) => REPOSITORY_SECRET_PATH,
        Some(REPOSITORY_SECRET_BY_NAME_PATH) => REPOSITORY_SECRET_BY_NAME_PATH,
        Some(BUILTIN_SECRET_PROVIDER_PATH) => BUILTIN_SECRET_PROVIDER_PATH,
        Some(BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH) => BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH,
        Some(RUNNER_ENROLLMENTS_PATH) => RUNNER_ENROLLMENTS_PATH,
        Some(RUNNER_ENROLLMENT_REDEEM_PATH) => RUNNER_ENROLLMENT_REDEEM_PATH,
        Some(_) => "other",
        None => "unmatched",
    }
}

const fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

const fn results_operations() -> [&'static str; 7] {
    [
        "create",
        "stage_block",
        "commit",
        "finalize",
        "list",
        "prepare_download",
        "read_block",
    ]
}

const fn results_operation_outcomes() -> [&'static str; 10] {
    [
        "success",
        "cancelled",
        "invalid_argument",
        "permission_denied",
        "not_found",
        "conflict",
        "failed_precondition",
        "resource_exhausted",
        "unavailable",
        "internal",
    ]
}

const fn repository_operations() -> [&'static str; 11] {
    [
        "create",
        "reserve_block",
        "complete_block",
        "commit_blocks",
        "begin_finalization",
        "load_finalization",
        "renew_finalization",
        "record_verification",
        "complete_finalization",
        "list",
        "resolve_download",
    ]
}

const fn repository_operation_outcomes() -> [&'static str; 9] {
    [
        "success",
        "cancelled",
        "not_found",
        "unauthorized",
        "conflict",
        "invalid_state",
        "resource_exhausted",
        "corrupt_data",
        "unavailable",
    ]
}

const fn blob_put_outcomes() -> [&'static str; 10] {
    [
        "created",
        "already_present",
        "cancelled",
        "not_found",
        "conflict",
        "integrity",
        "too_large",
        "unauthorized",
        "unavailable",
        "invalid_response",
    ]
}

const fn blob_get_outcomes() -> [&'static str; 9] {
    [
        "success",
        "cancelled",
        "not_found",
        "conflict",
        "integrity",
        "too_large",
        "unauthorized",
        "unavailable",
        "invalid_response",
    ]
}

const fn results_http_routes() -> [&'static str; 12] {
    [
        "cache_download",
        "cache_upload",
        "create_artifact",
        "create_cache",
        "download",
        "finalize_artifact",
        "finalize_cache",
        "get_cache_download_url",
        "get_signed_artifact_url",
        "list_artifacts",
        "unknown",
        "upload",
    ]
}

const fn results_operation(operation: ResultsOperation) -> &'static str {
    match operation {
        ResultsOperation::Create => "create",
        ResultsOperation::StageBlock => "stage_block",
        ResultsOperation::Commit => "commit",
        ResultsOperation::Finalize => "finalize",
        ResultsOperation::List => "list",
        ResultsOperation::PrepareDownload => "prepare_download",
        ResultsOperation::ReadBlock => "read_block",
    }
}

const fn results_operation_outcome(outcome: ResultsOperationOutcome) -> &'static str {
    match outcome {
        ResultsOperationOutcome::Success => "success",
        ResultsOperationOutcome::Cancelled => "cancelled",
        ResultsOperationOutcome::InvalidArgument => "invalid_argument",
        ResultsOperationOutcome::PermissionDenied => "permission_denied",
        ResultsOperationOutcome::NotFound => "not_found",
        ResultsOperationOutcome::Conflict => "conflict",
        ResultsOperationOutcome::FailedPrecondition => "failed_precondition",
        ResultsOperationOutcome::ResourceExhausted => "resource_exhausted",
        ResultsOperationOutcome::Unavailable => "unavailable",
        ResultsOperationOutcome::Internal => "internal",
    }
}

const fn results_transfer_direction(direction: ResultsTransferDirection) -> &'static str {
    match direction {
        ResultsTransferDirection::Upload => "upload",
        ResultsTransferDirection::Download => "download",
    }
}

const fn results_blob_operation(operation: ResultsBlobOperation) -> &'static str {
    match operation {
        ResultsBlobOperation::Put => "put",
        ResultsBlobOperation::Get => "get",
    }
}

const fn results_blob_outcome(outcome: ResultsBlobOperationOutcome) -> &'static str {
    match outcome {
        ResultsBlobOperationOutcome::Success => "success",
        ResultsBlobOperationOutcome::Created => "created",
        ResultsBlobOperationOutcome::AlreadyPresent => "already_present",
        ResultsBlobOperationOutcome::Cancelled => "cancelled",
        ResultsBlobOperationOutcome::NotFound => "not_found",
        ResultsBlobOperationOutcome::Conflict => "conflict",
        ResultsBlobOperationOutcome::Integrity => "integrity",
        ResultsBlobOperationOutcome::TooLarge => "too_large",
        ResultsBlobOperationOutcome::Unauthorized => "unauthorized",
        ResultsBlobOperationOutcome::Unavailable => "unavailable",
        ResultsBlobOperationOutcome::InvalidResponse => "invalid_response",
    }
}

const fn results_repository_operation(operation: ResultsRepositoryOperation) -> &'static str {
    match operation {
        ResultsRepositoryOperation::Create => "create",
        ResultsRepositoryOperation::ReserveBlock => "reserve_block",
        ResultsRepositoryOperation::CompleteBlock => "complete_block",
        ResultsRepositoryOperation::CommitBlocks => "commit_blocks",
        ResultsRepositoryOperation::BeginFinalization => "begin_finalization",
        ResultsRepositoryOperation::LoadFinalization => "load_finalization",
        ResultsRepositoryOperation::RenewFinalization => "renew_finalization",
        ResultsRepositoryOperation::RecordVerification => "record_verification",
        ResultsRepositoryOperation::CompleteFinalization => "complete_finalization",
        ResultsRepositoryOperation::List => "list",
        ResultsRepositoryOperation::ResolveDownload => "resolve_download",
    }
}

const fn results_repository_outcome(outcome: ResultsRepositoryOperationOutcome) -> &'static str {
    match outcome {
        ResultsRepositoryOperationOutcome::Success => "success",
        ResultsRepositoryOperationOutcome::Cancelled => "cancelled",
        ResultsRepositoryOperationOutcome::NotFound => "not_found",
        ResultsRepositoryOperationOutcome::Unauthorized => "unauthorized",
        ResultsRepositoryOperationOutcome::Conflict => "conflict",
        ResultsRepositoryOperationOutcome::InvalidState => "invalid_state",
        ResultsRepositoryOperationOutcome::ResourceExhausted => "resource_exhausted",
        ResultsRepositoryOperationOutcome::CorruptData => "corrupt_data",
        ResultsRepositoryOperationOutcome::Unavailable => "unavailable",
    }
}

const fn results_http_method_label(method: ResultsHttpMethod) -> &'static str {
    match method {
        ResultsHttpMethod::Get => "get",
        ResultsHttpMethod::Post => "post",
        ResultsHttpMethod::Put => "put",
        ResultsHttpMethod::Other => "other",
    }
}

const fn results_http_route_label(route: ResultsHttpRoute) -> &'static str {
    match route {
        ResultsHttpRoute::CreateArtifact => "create_artifact",
        ResultsHttpRoute::FinalizeArtifact => "finalize_artifact",
        ResultsHttpRoute::ListArtifacts => "list_artifacts",
        ResultsHttpRoute::GetSignedArtifactUrl => "get_signed_artifact_url",
        ResultsHttpRoute::Upload => "upload",
        ResultsHttpRoute::Download => "download",
        ResultsHttpRoute::CreateCache => "create_cache",
        ResultsHttpRoute::FinalizeCache => "finalize_cache",
        ResultsHttpRoute::GetCacheDownloadUrl => "get_cache_download_url",
        ResultsHttpRoute::CacheUpload => "cache_upload",
        ResultsHttpRoute::CacheDownload => "cache_download",
        ResultsHttpRoute::Unknown => "unknown",
    }
}

const fn results_http_outcome(status: ResultsHttpStatusClass) -> &'static str {
    match status {
        ResultsHttpStatusClass::Informational => "1xx",
        ResultsHttpStatusClass::Success => "2xx",
        ResultsHttpStatusClass::Redirection => "3xx",
        ResultsHttpStatusClass::ClientError => "4xx",
        ResultsHttpStatusClass::ServerError => "5xx",
        ResultsHttpStatusClass::Cancelled => "cancelled",
    }
}

const fn lease_poll_label_values() -> [(&'static str, &'static str, &'static str); 21] {
    [
        ("claimed", "new", "none"),
        ("claimed", "replay", "none"),
        ("no_work", "new", "none"),
        ("no_work", "replay", "none"),
        ("rejected", "new", "attempt_not_found"),
        ("rejected", "new", "attempt_not_queued"),
        ("rejected", "new", "no_longer_runnable"),
        ("rejected", "new", "not_routable"),
        ("rejected", "new", "slot_out_of_range"),
        ("rejected", "new", "slot_occupied"),
        ("rejected", "new", "scan_superseded"),
        ("rejected", "replay", "attempt_not_found"),
        ("rejected", "replay", "attempt_not_queued"),
        ("rejected", "replay", "no_longer_runnable"),
        ("rejected", "replay", "not_routable"),
        ("rejected", "replay", "slot_out_of_range"),
        ("rejected", "replay", "slot_occupied"),
        ("rejected", "replay", "scan_superseded"),
        ("error", "none", "invalid_request"),
        ("error", "none", "invalid_state"),
        ("error", "none", "unavailable"),
    ]
}

const fn workflow_outcomes() -> [&'static str; 6] {
    [
        "new",
        "replay",
        "error_materialization",
        "error_blob_store",
        "error_durable_store",
        "error_invalid_state",
    ]
}

const fn workflow_stages() -> [&'static str; 5] {
    ["prepare", "materialize", "encode", "publish", "commit"]
}

const fn handshake_outcomes() -> [&'static str; 9] {
    [
        "opened",
        "resumed",
        "rejected_unsupported_protocol",
        "rejected_unsupported_job_ir",
        "rejected_unauthorized",
        "rejected_session_not_resumable",
        "error_conflict",
        "error_unavailable",
        "error_internal",
    ]
}

const fn runner_message_kinds() -> [&'static str; 7] {
    [
        "lease_request",
        "lease_response",
        "heartbeat",
        "job_state",
        "job_result",
        "log_batch",
        "command_ack",
    ]
}

const fn runner_message_outcomes() -> [&'static str; 6] {
    [
        "success",
        "protocol_error",
        "error_forbidden",
        "error_conflict",
        "error_unavailable",
        "error_internal",
    ]
}

const fn runner_durable_kinds() -> [&'static str; 5] {
    [
        "lease_renewal",
        "lease_response",
        "job_result",
        "log_batch",
        "command_ack",
    ]
}

const fn lease_poll_labels(
    observation: LeasePollObservation,
) -> (&'static str, &'static str, &'static str) {
    match observation {
        LeasePollObservation::Claimed => ("claimed", "new", "none"),
        LeasePollObservation::ClaimedReplay => ("claimed", "replay", "none"),
        LeasePollObservation::NoWork => ("no_work", "new", "none"),
        LeasePollObservation::NoWorkReplay => ("no_work", "replay", "none"),
        LeasePollObservation::Rejected(reason) => ("rejected", "new", lease_rejection(reason)),
        LeasePollObservation::RejectedReplay(reason) => {
            ("rejected", "replay", lease_rejection(reason))
        }
        LeasePollObservation::Failed(failure) => ("error", "none", lease_failure(failure)),
    }
}

const fn lease_rejection(reason: LeaseClaimRejection) -> &'static str {
    match reason {
        LeaseClaimRejection::AttemptNotFound => "attempt_not_found",
        LeaseClaimRejection::AttemptNotQueued => "attempt_not_queued",
        LeaseClaimRejection::NoLongerRunnable => "no_longer_runnable",
        LeaseClaimRejection::NotRoutable => "not_routable",
        LeaseClaimRejection::SlotOutOfRange => "slot_out_of_range",
        LeaseClaimRejection::SlotOccupied => "slot_occupied",
        LeaseClaimRejection::ScanSuperseded => "scan_superseded",
    }
}

const fn lease_failure(failure: LeasePollFailure) -> &'static str {
    match failure {
        LeasePollFailure::InvalidRequest => "invalid_request",
        LeasePollFailure::InvalidState => "invalid_state",
        LeasePollFailure::Unavailable => "unavailable",
    }
}

const fn workflow_stage(stage: WorkflowAdmissionStage) -> &'static str {
    match stage {
        WorkflowAdmissionStage::Prepare => "prepare",
        WorkflowAdmissionStage::Materialize => "materialize",
        WorkflowAdmissionStage::Encode => "encode",
        WorkflowAdmissionStage::Publish => "publish",
        WorkflowAdmissionStage::Commit => "commit",
    }
}

const fn workflow_outcome(observation: WorkflowAdmissionObservation) -> &'static str {
    match observation {
        WorkflowAdmissionObservation::New { .. } => "new",
        WorkflowAdmissionObservation::Replay => "replay",
        WorkflowAdmissionObservation::Failed(WorkflowAdmissionFailure::Materialization) => {
            "error_materialization"
        }
        WorkflowAdmissionObservation::Failed(WorkflowAdmissionFailure::BlobStore) => {
            "error_blob_store"
        }
        WorkflowAdmissionObservation::Failed(WorkflowAdmissionFailure::DurableStore) => {
            "error_durable_store"
        }
        WorkflowAdmissionObservation::Failed(WorkflowAdmissionFailure::InvalidState) => {
            "error_invalid_state"
        }
    }
}

const fn runner_handshake_outcome(observation: RunnerHandshakeOutcome) -> &'static str {
    match observation {
        RunnerHandshakeOutcome::Opened => "opened",
        RunnerHandshakeOutcome::Resumed => "resumed",
        RunnerHandshakeOutcome::Rejected(rejection) => handshake_rejection(rejection),
        RunnerHandshakeOutcome::Failed(failure) => runner_failure(failure),
    }
}

const fn handshake_rejection(rejection: RunnerHandshakeRejection) -> &'static str {
    match rejection {
        RunnerHandshakeRejection::UnsupportedProtocol => "rejected_unsupported_protocol",
        RunnerHandshakeRejection::UnsupportedJobIr => "rejected_unsupported_job_ir",
        RunnerHandshakeRejection::Unauthorized => "rejected_unauthorized",
        RunnerHandshakeRejection::SessionNotResumable => "rejected_session_not_resumable",
    }
}

const fn runner_message_kind(kind: RunnerControlMessageKind) -> &'static str {
    match kind {
        RunnerControlMessageKind::LeaseRequest => "lease_request",
        RunnerControlMessageKind::LeaseResponse => "lease_response",
        RunnerControlMessageKind::Heartbeat => "heartbeat",
        RunnerControlMessageKind::JobState => "job_state",
        RunnerControlMessageKind::JobResult => "job_result",
        RunnerControlMessageKind::LogBatch => "log_batch",
        RunnerControlMessageKind::CommandAck => "command_ack",
    }
}

const fn runner_message_outcome(outcome: RunnerControlMessageOutcome) -> &'static str {
    match outcome {
        RunnerControlMessageOutcome::Success => "success",
        RunnerControlMessageOutcome::ProtocolError => "protocol_error",
        RunnerControlMessageOutcome::Failed(failure) => runner_failure(failure),
    }
}

const fn runner_failure(failure: RunnerControlFailure) -> &'static str {
    match failure {
        RunnerControlFailure::Forbidden => "error_forbidden",
        RunnerControlFailure::Conflict => "error_conflict",
        RunnerControlFailure::Unavailable => "error_unavailable",
        RunnerControlFailure::Internal => "error_internal",
    }
}

const fn runner_durable_kind(kind: RunnerDurableMessageKind) -> &'static str {
    match kind {
        RunnerDurableMessageKind::LeaseRenewal => "lease_renewal",
        RunnerDurableMessageKind::LeaseResponse => "lease_response",
        RunnerDurableMessageKind::JobResult => "job_result",
        RunnerDurableMessageKind::LogBatch => "log_batch",
        RunnerDurableMessageKind::CommandAck => "command_ack",
    }
}

const fn runner_transport_request_labels(
    observation: RunnerTransportRequestObservation,
) -> (&'static str, &'static str, &'static str) {
    match observation {
        RunnerTransportRequestObservation::Cancelled { route } => {
            (runner_transport_route(route), "cancelled", "cancelled")
        }
        RunnerTransportRequestObservation::AdmissionOverloaded => {
            ("unknown", "admission", "overloaded")
        }
        RunnerTransportRequestObservation::HeadRejected { route, reason } => (
            runner_transport_route(route),
            "head",
            runner_transport_head_rejection(reason),
        ),
        RunnerTransportRequestObservation::AuthenticationRejected { route, reason } => (
            runner_transport_route(route),
            "authentication",
            runner_transport_authentication_rejection(reason),
        ),
        RunnerTransportRequestObservation::BodyRejected { route, reason } => (
            runner_transport_route(route),
            "body",
            runner_transport_body_rejection(reason),
        ),
        RunnerTransportRequestObservation::DecodeRejected { route, reason } => (
            runner_transport_route(route),
            "decode",
            runner_transport_decode_rejection(reason),
        ),
        RunnerTransportRequestObservation::ApplicationRejected { route, reason } => (
            runner_transport_route(route),
            "application",
            runner_transport_application_rejection(reason),
        ),
        RunnerTransportRequestObservation::ResponseRejected { route, reason } => (
            runner_transport_route(route),
            "response",
            runner_transport_response_rejection(reason),
        ),
        RunnerTransportRequestObservation::Succeeded { route } => {
            (runner_transport_route(route), "response", "success")
        }
    }
}

const fn runner_transport_route(route: RunnerTransportRoute) -> &'static str {
    match route {
        RunnerTransportRoute::Unknown => "unknown",
        RunnerTransportRoute::Handshake => "handshake",
        RunnerTransportRoute::Sync => "sync",
        RunnerTransportRoute::EphemeralSecrets => "ephemeral_secrets",
    }
}

const fn runner_transport_head_rejection(reason: RunnerTransportHeadRejection) -> &'static str {
    match reason {
        RunnerTransportHeadRejection::HttpVersion => "http_version",
        RunnerTransportHeadRejection::Method => "method",
        RunnerTransportHeadRejection::NotFound => "not_found",
        RunnerTransportHeadRejection::UnsupportedMediaType => "unsupported_media_type",
        RunnerTransportHeadRejection::LengthRequired => "length_required",
        RunnerTransportHeadRejection::InvalidContentLength => "invalid_content_length",
        RunnerTransportHeadRejection::BodyTooLarge => "body_too_large",
    }
}

const fn runner_transport_authentication_rejection(
    reason: RunnerTransportAuthenticationRejection,
) -> &'static str {
    match reason {
        RunnerTransportAuthenticationRejection::Untrusted => "untrusted",
        RunnerTransportAuthenticationRejection::Expired => "expired",
        RunnerTransportAuthenticationRejection::Unavailable => "unavailable",
        RunnerTransportAuthenticationRejection::Timeout => "timeout",
    }
}

const fn runner_transport_body_rejection(reason: RunnerTransportBodyRejection) -> &'static str {
    match reason {
        RunnerTransportBodyRejection::TooLarge => "too_large",
        RunnerTransportBodyRejection::Invalid => "invalid",
        RunnerTransportBodyRejection::Transport => "transport",
        RunnerTransportBodyRejection::Timeout => "timeout",
    }
}

const fn runner_transport_decode_rejection(reason: RunnerTransportDecodeRejection) -> &'static str {
    match reason {
        RunnerTransportDecodeRejection::InvalidProtobuf => "invalid_protobuf",
        RunnerTransportDecodeRejection::RouteMismatch => "route_mismatch",
        RunnerTransportDecodeRejection::Canonicalization => "canonicalization",
    }
}

const fn runner_transport_application_rejection(
    reason: RunnerTransportApplicationRejection,
) -> &'static str {
    match reason {
        RunnerTransportApplicationRejection::Forbidden => "forbidden",
        RunnerTransportApplicationRejection::Conflict => "conflict",
        RunnerTransportApplicationRejection::Unavailable => "unavailable",
        RunnerTransportApplicationRejection::Internal => "internal",
        RunnerTransportApplicationRejection::Timeout => "timeout",
    }
}

const fn runner_transport_response_rejection(
    reason: RunnerTransportResponseRejection,
) -> &'static str {
    match reason {
        RunnerTransportResponseRejection::InvalidCorrelation => "invalid_correlation",
        RunnerTransportResponseRejection::Encoding => "encoding",
        RunnerTransportResponseRejection::TooLarge => "too_large",
    }
}

fn unix_timestamp_seconds() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use prometheus_client::encoding::prometheus_protobuf;

    use super::*;

    mod schema_contract {
        include!("../../../automata-ci-metrics/tests/support/schema_contract.rs");
    }

    const CARDINALITY_MANIFEST: &str =
        include_str!("../../../../deploy/observability/cardinality.json");

    #[test]
    fn production_histogram_preserves_classic_buckets_and_exports_native_spans() {
        let mut registry = Registry::default();
        let metrics = ControlSemanticMetrics::register(&mut registry);
        metrics.lease_candidates.observe(2.0);

        let families = prometheus_protobuf::encode(&registry).expect("protobuf encoding");
        let family = families
            .iter()
            .find(|family| family.name == "control_plane_lease_poll_candidates")
            .expect("production lease-candidate histogram family");
        let histogram = family
            .metric
            .first()
            .and_then(|metric| metric.histogram.as_ref())
            .expect("histogram sample");

        assert_eq!(histogram.sample_count, 1);
        assert!((histogram.sample_sum - 2.0).abs() <= f64::EPSILON);
        assert_eq!(histogram.schema, 3);
        assert!(histogram.positive_span.iter().any(|span| span.length > 0));
        assert!(!histogram.positive_delta.is_empty());
        assert_eq!(
            histogram
                .bucket
                .iter()
                .map(|bucket| bucket.upper_bound)
                .collect::<Vec<_>>(),
            CANDIDATE_BUCKETS
                .into_iter()
                .chain([f64::MAX])
                .collect::<Vec<_>>()
        );

        let product = ControlPlaneMetrics::new(BuildInfo::current()).expect("control metrics");
        let exposition = product
            .exporter()
            .encode_openmetrics()
            .expect("OpenMetrics exposition");
        assert_eq!(
            openmetrics_histogram_label_sets(exposition.as_str()),
            schema_contract::expected_histogram_label_sets(
                CARDINALITY_MANIFEST,
                &["common", "control_plane"],
            )
        );
    }

    fn openmetrics_histogram_label_sets(exposition: &str) -> usize {
        exposition
            .lines()
            .filter_map(|line| line.strip_prefix("# TYPE "))
            .filter_map(|line| line.strip_suffix(" histogram"))
            .map(|family| {
                let count = format!("{family}_count");
                exposition
                    .lines()
                    .filter(|line| {
                        line.strip_prefix(&count).is_some_and(|suffix| {
                            suffix.starts_with('{') || suffix.starts_with(' ')
                        })
                    })
                    .count()
            })
            .sum()
    }

    #[test]
    fn human_http_route_labels_cover_every_auth_setup_and_management_template() {
        let rbac_routes = [
            "/settings/access/users",
            "/settings/access/users/{principal_id}",
            "/settings/access/users/{principal_id}/status",
            "/settings/access/roles",
            "/settings/access/roles/{role_id}",
            "/settings/access/roles/{role_id}/delete",
            "/settings/access/roles/{role_id}/permissions/{permission}",
            "/settings/access/direct-bindings",
            "/settings/access/direct-bindings/{binding_id}/revoke",
        ];
        for route in rbac_routes {
            assert_eq!(http_route(Some(route)), RBAC_SETTINGS_ROUTE);
            assert!(!HTTP_ROUTE_LABELS.contains(&route));
        }
        assert!(HTTP_ROUTE_LABELS.contains(&RBAC_SETTINGS_ROUTE));

        let operational_routes = [
            "/setup",
            "/{owner}/{repository}/settings/access",
            REPOSITORY_SECRETS_SETTINGS_PATH,
            GITHUB_WEB_BEGIN_PATH,
            GITHUB_WEB_CALLBACK_PATH,
            GITHUB_WEB_LOGOUT_PATH,
            GITHUB_WEBHOOK_PATH,
            CLI_SESSION_PATH,
            GITHUB_SETUP_WEB_BEGIN_PATH,
            GITHUB_SETUP_DEVICE_BEGIN_PATH,
            GITHUB_SETUP_DEVICE_POLL_PATH,
            USERS_PATH,
            USER_PATH,
            ROLES_PATH,
            ROLE_PATH,
            ROLE_PERMISSION_PATH,
            DIRECT_BINDINGS_PATH,
            DIRECT_BINDING_PATH,
            PROTECTED_ENVIRONMENT_REVIEW_PATH,
            WORKFLOW_RERUN_PATH,
            GITHUB_REPOSITORY_SECRET_RESOLUTION_PATH,
            REPOSITORY_SECRETS_PATH,
            REPOSITORY_SECRET_PATH,
            REPOSITORY_SECRET_BY_NAME_PATH,
            BUILTIN_SECRET_PROVIDER_PATH,
            BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH,
            RUNNER_ENROLLMENTS_PATH,
            RUNNER_ENROLLMENT_REDEEM_PATH,
            SHARD_CAPABILITIES_PATH,
            DELEGATED_ACTOR_VIEWER_PATH,
        ];

        for route in operational_routes {
            assert_eq!(http_route(Some(route)), route);
            assert!(HTTP_ROUTE_LABELS.contains(&route));
        }
        assert_eq!(
            http_route(Some(
                "/api/v1/repositories/aaaaaaaa-1111-4111-8111-111111111111/attempts/22222222-2222-4222-8222-222222222222/environment/reviews"
            )),
            "other",
            "raw protected-environment identities must never become metric labels"
        );
        for route in [GITHUB_DEVICE_BEGIN_PATH, GITHUB_DEVICE_POLL_PATH] {
            assert_eq!(http_route(Some(route)), GITHUB_DEVICE_ROUTE);
            assert!(!HTTP_ROUTE_LABELS.contains(&route));
        }
        assert!(HTTP_ROUTE_LABELS.contains(&GITHUB_DEVICE_ROUTE));
        for route in [
            REPOSITORY_SECRET_REPLACE_PATH,
            REPOSITORY_SECRET_DELETE_PATH,
            REPOSITORY_SECRET_PROVIDER_ACTIVATE_PATH,
        ] {
            assert_eq!(
                http_route(Some(route)),
                REPOSITORY_SECRET_BROWSER_MUTATION_ROUTE
            );
            assert!(!HTTP_ROUTE_LABELS.contains(&route));
        }
        assert!(HTTP_ROUTE_LABELS.contains(&REPOSITORY_SECRET_BROWSER_MUTATION_ROUTE));
        assert_eq!(http_route(Some("/private/unregistered/path")), "other");
        assert_eq!(http_route(None), "unmatched");
        assert_eq!(
            HTTP_ROUTE_LABELS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            HTTP_ROUTE_LABELS.len(),
            "the fixed route domain must not contain duplicate series"
        );
    }
}
