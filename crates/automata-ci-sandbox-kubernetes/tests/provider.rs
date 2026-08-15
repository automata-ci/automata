use std::{
    convert::Infallible,
    num::NonZeroU16,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use automata_ci_core::{
    EnvironmentProfile, EnvironmentProfileId, JobResourceAllocation, OperationId, ResourceCapacity,
    Sha256Digest,
};
use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, ExecutionArgv, ExecutionEnvironment,
    ImmutableImage, NetworkPolicy, NeverCancelled, OperationOutcome, ProviderError,
    ProviderErrorKind, ProviderId, ProviderStage, ResourceLimits, RootFilesystemPolicy, RunnerId,
    SandboxCapability, SandboxCustody, SandboxEnvironment, SandboxGeneration, SandboxHandle,
    SandboxProvider, SandboxSpec, SandboxState, TargetPath,
};
use automata_ci_sandbox_kubernetes::{
    KUBERNETES_PROVIDER_ID, KubernetesSandboxConfig, KubernetesSandboxProvider,
    VerifiedEphemeralStorageEnforcement, VerifiedNetworkIsolation, VerifiedProcessLimitEnforcement,
};
use http::{Method, Request, Response, StatusCode};
use kube::{Client, client::Body};
use serde_json::{Value, json};
use tower::service_fn;

const NAMESPACE: &str = "automata-runners";
const MANAGED_LABEL: &str = "ci.automata.dev/managed";
const SANDBOX_LABEL: &str = "ci.automata.dev/sandbox";
const SCHEMA_LABEL: &str = "ci.automata.dev/sandbox-schema";
const CUSTODY_KIND_LABEL: &str = "ci.automata.dev/custody-kind";
const CUSTODY_RUNNER_LABEL: &str = "ci.automata.dev/custody-runner";
const CUSTODY_SLOT_LABEL: &str = "ci.automata.dev/custody-slot";
const GENERATION_ANNOTATION: &str = "ci.automata.dev/generation";
const FINGERPRINT_ANNOTATION: &str = "ci.automata.dev/spec-sha256";

#[derive(Clone, Debug)]
struct TestCancellation(Arc<AtomicBool>);

impl TestCancellation {
    fn pending() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn cancelled() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

impl Cancellation for TestCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: Method,
    uri: String,
    body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default)]
enum PodView {
    #[default]
    Running,
    Pending,
    Stopped,
    MissingUid,
    MalformedGeneration,
}

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Independent fake-server fault injection switches.
struct FakeState {
    requests: Vec<CapturedRequest>,
    pod: Option<Value>,
    policy: Option<Value>,
    conflict_pod_create: bool,
    conflict_policy_create: bool,
    corrupt_policy_fingerprint: bool,
    mutate_pod_create: bool,
    mutate_policy_create: bool,
    pod_view: PodView,
    cancel_after_request: Option<(usize, Arc<AtomicBool>)>,
    next_response: Option<(StatusCode, Vec<u8>)>,
    delay_next: Option<Duration>,
}

#[derive(Clone, Default)]
struct FakeKube(Arc<Mutex<FakeState>>);

impl FakeKube {
    fn client(&self) -> Client {
        let fake = self.clone();
        let service = service_fn(move |request: Request<Body>| {
            let fake = fake.clone();
            async move { fake.respond(request).await }
        });
        Client::new(service, NAMESPACE)
    }

    async fn respond(&self, request: Request<Body>) -> Result<Response<Body>, Infallible> {
        let (parts, body) = request.into_parts();
        let body = body
            .collect_bytes()
            .await
            .expect("collect fake Kubernetes request")
            .to_vec();
        let delay = self.0.lock().expect("fake state lock").delay_next.take();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let mut state = self.0.lock().expect("fake state lock");
        let request_index = state.requests.len();
        let method = parts.method;
        let uri = parts.uri.to_string();
        state.requests.push(CapturedRequest {
            method: method.clone(),
            uri: uri.clone(),
            body: body.clone(),
        });

        let response = if let Some(response) = state.next_response.take() {
            response
        } else {
            Self::standard_response(&mut state, &method, &uri, &body)
        };
        if state
            .cancel_after_request
            .as_ref()
            .is_some_and(|(index, _)| *index == request_index)
        {
            let (_, cancellation) = state
                .cancel_after_request
                .take()
                .expect("matched cancellation");
            cancellation.store(true, Ordering::SeqCst);
        }
        Ok(json_response(response.0, response.1))
    }

    fn standard_response(
        state: &mut FakeState,
        method: &Method,
        uri: &str,
        body: &[u8],
    ) -> (StatusCode, Vec<u8>) {
        let is_policy = uri.contains("/networkpolicies");
        match *method {
            Method::GET => {
                let resource = if is_policy {
                    state.policy.as_ref().map(|policy| {
                        let mut policy = policy.clone();
                        policy["metadata"]["uid"] = json!("policy-uid");
                        policy["metadata"]["resourceVersion"] = json!("policy-version");
                        if state.corrupt_policy_fingerprint {
                            policy["metadata"]["annotations"][FINGERPRINT_ANNOTATION] =
                                json!("different");
                        }
                        policy
                    })
                } else {
                    state
                        .pod
                        .as_ref()
                        .map(|pod| pod_response(pod, state.pod_view))
                };
                resource.map_or_else(
                    || api_error(StatusCode::NOT_FOUND),
                    |resource| {
                        (
                            StatusCode::OK,
                            serde_json::to_vec(&resource).expect("serialize fake resource"),
                        )
                    },
                )
            }
            Method::POST => {
                let mut resource: Value =
                    serde_json::from_slice(body).expect("decode created Kubernetes resource");
                if is_policy && std::mem::take(&mut state.mutate_policy_create) {
                    resource["spec"]["ingress"] = json!([{}]);
                }
                if !is_policy && std::mem::take(&mut state.mutate_pod_create) {
                    resource["spec"]["hostNetwork"] = json!(true);
                }
                let conflict = if is_policy {
                    state.policy = Some(resource.clone());
                    std::mem::take(&mut state.conflict_policy_create)
                } else {
                    state.pod = Some(resource.clone());
                    std::mem::take(&mut state.conflict_pod_create)
                };
                if conflict {
                    api_error(StatusCode::CONFLICT)
                } else {
                    (
                        StatusCode::OK,
                        serde_json::to_vec(&resource).expect("serialize created resource"),
                    )
                }
            }
            Method::DELETE => {
                let removed = if is_policy {
                    state.policy.take()
                } else {
                    state.pod.take()
                };
                removed.map_or_else(
                    || api_error(StatusCode::NOT_FOUND),
                    |resource| {
                        (
                            StatusCode::OK,
                            serde_json::to_vec(&resource).expect("serialize deleted resource"),
                        )
                    },
                )
            }
            _ => api_error(StatusCode::METHOD_NOT_ALLOWED),
        }
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.0.lock().expect("fake state lock").requests.clone()
    }

    fn request_count(&self) -> usize {
        self.0.lock().expect("fake state lock").requests.len()
    }

    fn conflict_on_create(&self) {
        let mut state = self.0.lock().expect("fake state lock");
        state.conflict_policy_create = true;
        state.conflict_pod_create = true;
    }

    fn corrupt_policy_fingerprint(&self) {
        self.0
            .lock()
            .expect("fake state lock")
            .corrupt_policy_fingerprint = true;
    }

    fn mutate_policy_create(&self) {
        self.0.lock().expect("fake state lock").mutate_policy_create = true;
    }

    fn mutate_pod_create(&self) {
        self.0.lock().expect("fake state lock").mutate_pod_create = true;
    }

    fn cancel_after(&self, request_index: usize, cancellation: &TestCancellation) {
        self.0.lock().expect("fake state lock").cancel_after_request =
            Some((request_index, Arc::clone(&cancellation.0)));
    }

    fn set_pod_view(&self, view: PodView) {
        self.0.lock().expect("fake state lock").pod_view = view;
    }

    fn override_next(&self, status: StatusCode, body: impl Into<Vec<u8>>) {
        self.0.lock().expect("fake state lock").next_response = Some((status, body.into()));
    }

    fn delay_next(&self, delay: Duration) {
        self.0.lock().expect("fake state lock").delay_next = Some(delay);
    }

    fn replace_custody(&self, kind: &str, runner: RunnerId, slot: u16) {
        let mut state = self.0.lock().expect("fake state lock");
        let replace = |resource: &mut Value| {
            resource["metadata"]["labels"][CUSTODY_KIND_LABEL] = json!(kind);
            resource["metadata"]["labels"][CUSTODY_RUNNER_LABEL] = json!(runner.to_string());
            resource["metadata"]["labels"][CUSTODY_SLOT_LABEL] = json!(slot.to_string());
        };
        if let Some(resource) = state.pod.as_mut() {
            replace(resource);
        }
        if let Some(resource) = state.policy.as_mut() {
            replace(resource);
        }
    }

    fn replace_schema(&self, schema: &str) {
        let mut state = self.0.lock().expect("fake state lock");
        let replace = |resource: &mut Value| {
            resource["metadata"]["labels"][SCHEMA_LABEL] = json!(schema);
        };
        if let Some(resource) = state.pod.as_mut() {
            replace(resource);
        }
        if let Some(resource) = state.policy.as_mut() {
            replace(resource);
        }
    }
}

fn pod_response(pod: &Value, view: PodView) -> Value {
    let mut pod = pod.clone();
    pod["metadata"]["resourceVersion"] = json!("pod-version");
    pod["metadata"]["uid"] = json!("pod-uid");
    let phase = match view {
        PodView::Pending => "Pending",
        PodView::Stopped => "Failed",
        PodView::Running | PodView::MissingUid | PodView::MalformedGeneration => "Running",
    };
    pod["status"] = json!({
        "phase": phase,
        "containerStatuses": [{
            "name": "job",
            "ready": matches!(
                view,
                PodView::Running | PodView::MissingUid | PodView::MalformedGeneration
            ),
            "restartCount": 0,
            "image": "immutable",
            "imageID": "immutable-id"
        }]
    });
    if matches!(view, PodView::MissingUid) {
        pod["metadata"]
            .as_object_mut()
            .expect("metadata")
            .remove("uid");
    }
    if matches!(view, PodView::MalformedGeneration) {
        pod["metadata"]["annotations"][GENERATION_ANNOTATION] = json!("malformed");
    }
    pod
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("fake Kubernetes response")
}

fn api_error(status: StatusCode) -> (StatusCode, Vec<u8>) {
    let reason = match status {
        StatusCode::NOT_FOUND => "NotFound",
        StatusCode::CONFLICT => "AlreadyExists",
        _ => "Failure",
    };
    (
        status,
        serde_json::to_vec(&json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "message": "sanitized fake Kubernetes failure",
            "reason": reason,
            "code": status.as_u16()
        }))
        .expect("serialize Kubernetes error"),
    )
}

fn immutable_image(repository: &str, byte: u8) -> ImmutableImage {
    ImmutableImage::new(format!(
        "{repository}@sha256:{}",
        format!("{byte:02x}").repeat(32)
    ))
    .expect("immutable image")
}

fn config() -> KubernetesSandboxConfig {
    KubernetesSandboxConfig::new(
        NAMESPACE,
        immutable_image("registry.example/automata/guest", 1),
        VerifiedNetworkIsolation,
    )
    .expect("config")
    .with_verified_ephemeral_storage(VerifiedEphemeralStorageEnforcement)
    .with_verified_process_limit(VerifiedProcessLimitEnforcement::new(512).expect("process limit"))
    .with_gpu_resource_name("nvidia.com/gpu")
    .expect("GPU mapping")
}

fn sandbox_spec() -> SandboxSpec {
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("example.com/linux").expect("profile id"),
        Sha256Digest::from_bytes([2; 32]),
    );
    let workspace = TargetPath::posix("/workspace").expect("workspace");
    let environment = SandboxEnvironment::new(
        profile,
        immutable_image("registry.example/automata/job", 3),
        ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("program"),
            vec!["infinity".into()],
        )
        .expect("argv"),
        workspace.clone(),
        ExecutionEnvironment::empty(),
    )
    .expect("environment");
    let allocation = JobResourceAllocation::new(
        ResourceCapacity::new(250, 256 * 1024 * 1024, 1024 * 1024 * 1024, 1),
        ResourceCapacity::new(1_500, 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024, 1),
    )
    .expect("allocation");
    SandboxSpec::new(
        OperationId::new(),
        SandboxGeneration::new(7).expect("generation"),
        SandboxCustody::Job {
            runner_id: RunnerId::new(),
            slot_ordinal: NonZeroU16::new(7).expect("non-zero slot"),
        },
        environment,
        workspace,
        NetworkPolicy::Disabled,
        RootFilesystemPolicy::ReadOnly,
        ResourceLimits::new(1024 * 1024 * 1024, 1_500, 512).expect("limits"),
    )
    .with_resource_allocation(allocation)
}

fn sandbox_name(spec: &SandboxSpec) -> String {
    format!(
        "a-{}-{}",
        spec.operation_id().as_uuid().simple(),
        spec.generation().get()
    )
}

fn sandbox_handle(spec: &SandboxSpec) -> SandboxHandle {
    SandboxHandle::new(
        ProviderId::new(KUBERNETES_PROVIDER_ID).expect("provider id"),
        sandbox_name(spec),
    )
    .expect("sandbox handle")
}

fn destroy_request(spec: &SandboxSpec) -> DestroySandbox {
    DestroySandbox::new(OperationId::new(), sandbox_handle(spec), spec.generation())
}

fn test_provider(fake: &FakeKube) -> KubernetesSandboxProvider {
    KubernetesSandboxProvider::new(fake.client(), config()).expect("Kubernetes provider")
}

fn assert_error(
    error: &ProviderError,
    kind: ProviderErrorKind,
    stage: ProviderStage,
    outcome: OperationOutcome,
) {
    assert_eq!(error.kind(), kind);
    assert_eq!(error.stage(), stage);
    assert_eq!(error.outcome(), outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // One lifecycle test verifies the full request transcript.
async fn complete_lifecycle_uses_exact_owned_objects_and_delete_preconditions() {
    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let spec = sandbox_spec();
    let handle = sandbox_handle(&spec);

    let record = provider
        .create(&spec, &NeverCancelled)
        .expect("create sandbox");
    let replayed = provider
        .create(&spec, &NeverCancelled)
        .expect("idempotent create replay");
    let inspection = provider
        .inspect(&handle, &NeverCancelled)
        .expect("inspect sandbox");
    let endpoint = provider
        .attach(&handle, &NeverCancelled)
        .expect("attach sandbox");
    let disposition = provider
        .destroy(&destroy_request(&spec), &NeverCancelled)
        .expect("destroy sandbox");
    let replay = provider
        .destroy(&destroy_request(&spec), &NeverCancelled)
        .expect("idempotent destroy replay");

    assert_eq!(record.handle(), &handle);
    assert_eq!(record.generation(), spec.generation());
    assert_eq!(record.profile(), spec.profile().attestation());
    assert_eq!(record.state(), SandboxState::Running);
    assert_eq!(replayed, record);
    assert_eq!(inspection.handle(), &handle);
    assert_eq!(inspection.generation(), spec.generation());
    assert_eq!(inspection.custody(), spec.custody());
    assert_eq!(inspection.profile(), spec.profile().attestation());
    assert_eq!(inspection.state(), SandboxState::Running);
    assert_eq!(endpoint.handle(), &handle);
    assert_eq!(disposition, DestroyDisposition::Destroyed);
    assert_eq!(replay, DestroyDisposition::AlreadyAbsent);

    let requests = fake.requests();
    let name = sandbox_name(&spec);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(
        requests[0].uri,
        format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies/{name}-deny")
    );
    assert_eq!(requests[1].method, Method::POST);
    assert_eq!(
        requests[1].uri,
        format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies?")
    );
    assert_eq!(requests[2].method, Method::GET);
    assert_eq!(
        requests[2].uri,
        format!("/api/v1/namespaces/{NAMESPACE}/pods/{name}")
    );
    assert_eq!(requests[3].method, Method::POST);
    assert_eq!(
        requests[3].uri,
        format!("/api/v1/namespaces/{NAMESPACE}/pods?")
    );
    let policy_body: Value = serde_json::from_slice(&requests[1].body).expect("policy body");
    let pod_body: Value = serde_json::from_slice(&requests[3].body).expect("Pod body");
    assert_eq!(policy_body["metadata"]["labels"][MANAGED_LABEL], "true");
    assert_eq!(policy_body["metadata"]["labels"][SANDBOX_LABEL], name);
    assert_eq!(policy_body["metadata"]["labels"][SCHEMA_LABEL], "2");
    assert_eq!(
        policy_body["spec"]["policyTypes"],
        json!(["Ingress", "Egress"])
    );
    assert_eq!(pod_body["metadata"]["name"], name);
    assert_eq!(pod_body["spec"]["automountServiceAccountToken"], false);
    assert_eq!(
        pod_body["metadata"]["annotations"][FINGERPRINT_ANNOTATION],
        policy_body["metadata"]["annotations"][FINGERPRINT_ANNOTATION]
    );

    let deletes = requests
        .iter()
        .filter(|request| request.method == Method::DELETE)
        .collect::<Vec<_>>();
    assert_eq!(deletes.len(), 2);
    let pod_delete: Value = serde_json::from_slice(&deletes[0].body).expect("Pod delete body");
    let policy_delete: Value =
        serde_json::from_slice(&deletes[1].body).expect("policy delete body");
    assert_eq!(
        pod_delete["preconditions"],
        json!({"resourceVersion": "pod-version", "uid": "pod-uid"})
    );
    assert_eq!(
        policy_delete["preconditions"],
        json!({"resourceVersion": "policy-version", "uid": "policy-uid"})
    );
    let pod_delete_index = requests
        .iter()
        .position(|request| {
            request.method == Method::DELETE && !request.uri.contains("networkpolicies")
        })
        .expect("Pod DELETE");
    let policy_delete_index = requests
        .iter()
        .position(|request| {
            request.method == Method::DELETE && request.uri.contains("networkpolicies")
        })
        .expect("NetworkPolicy DELETE");
    assert!(
        requests[pod_delete_index + 1..policy_delete_index]
            .iter()
            .any(|request| request.method == Method::GET && request.uri.contains("/pods/")),
        "NetworkPolicy deletion must wait until Pod absence is observed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_rejects_admission_mutation_of_security_objects() {
    let spec = sandbox_spec();

    let fake = FakeKube::default();
    fake.mutate_policy_create();
    let policy_error = test_provider(&fake)
        .create(&spec, &NeverCancelled)
        .expect_err("mutated policy must fail closed");
    assert_error(
        &policy_error,
        ProviderErrorKind::Conflict,
        ProviderStage::CreateSandbox,
        OperationOutcome::Uncertain,
    );

    let fake = FakeKube::default();
    fake.mutate_pod_create();
    let pod_error = test_provider(&fake)
        .create(&spec, &NeverCancelled)
        .expect_err("mutated Pod must fail closed");
    assert_error(
        &pod_error,
        ProviderErrorKind::Conflict,
        ProviderStage::CreateSandbox,
        OperationOutcome::Uncertain,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_recovers_both_create_conflicts_by_verifying_stored_fingerprints() {
    let fake = FakeKube::default();
    fake.conflict_on_create();
    let provider = test_provider(&fake);
    let spec = sandbox_spec();

    let record = provider
        .create(&spec, &NeverCancelled)
        .expect("conflict recovery");

    assert_eq!(record.state(), SandboxState::Running);
    let requests = fake.requests();
    assert_eq!(requests.len(), 7);
    assert_eq!(
        requests
            .iter()
            .map(|request| request.method.clone())
            .collect::<Vec<_>>(),
        [
            Method::GET,
            Method::POST,
            Method::GET,
            Method::GET,
            Method::POST,
            Method::GET,
            Method::GET,
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_reports_and_revalidates_exact_custody_and_current_schema() {
    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let spec = sandbox_spec();
    let handle = sandbox_handle(&spec);
    provider
        .create(&spec, &NeverCancelled)
        .expect("create current Kubernetes resources");

    let wrong_runner = RunnerId::new();
    fake.replace_custody("job", wrong_runner, 7);
    assert_eq!(
        provider
            .inspect(&handle, &NeverCancelled)
            .expect("custody is explicit recovery evidence")
            .custody(),
        SandboxCustody::Job {
            runner_id: wrong_runner,
            slot_ordinal: NonZeroU16::new(7).expect("non-zero slot"),
        }
    );
    let error = provider
        .create(&spec, &NeverCancelled)
        .expect_err("replay must reject a wrong runner");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);

    fake.replace_custody("job", spec.custody().runner_id(), 2);
    assert_eq!(
        provider
            .inspect(&handle, &NeverCancelled)
            .expect("job slot is explicit recovery evidence")
            .custody(),
        SandboxCustody::Job {
            runner_id: spec.custody().runner_id(),
            slot_ordinal: NonZeroU16::new(2).expect("non-zero slot"),
        }
    );
    let error = provider
        .create(&spec, &NeverCancelled)
        .expect_err("replay must reject a wrong slot");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);

    fake.replace_schema("1");
    let error = provider
        .inspect(&handle, &NeverCancelled)
        .expect_err("schema-1 Kubernetes resources must not recover");
    assert_eq!(error.kind(), ProviderErrorKind::OwnershipMismatch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflict_and_cancellation_failures_keep_exact_recovery_identity() {
    let spec = sandbox_spec();
    let fake = FakeKube::default();
    fake.conflict_on_create();
    fake.corrupt_policy_fingerprint();
    let provider = test_provider(&fake);
    let conflict = provider
        .create(&spec, &NeverCancelled)
        .expect_err("fingerprint mismatch must reject replay");
    assert_error(
        &conflict,
        ProviderErrorKind::Conflict,
        ProviderStage::CreateSandbox,
        OperationOutcome::Uncertain,
    );
    assert_eq!(conflict.recovery_handle(), Some(&sandbox_handle(&spec)));

    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let cancellation = TestCancellation::pending();
    fake.cancel_after(1, &cancellation);
    let cancelled = provider
        .create(&spec, &cancellation)
        .expect_err("cancellation after policy creation must be uncertain");
    assert_error(
        &cancelled,
        ProviderErrorKind::Cancelled,
        ProviderStage::CreateSandbox,
        OperationOutcome::Uncertain,
    );
    assert_eq!(cancelled.recovery_handle(), Some(&sandbox_handle(&spec)));
    assert_eq!(fake.request_count(), 2);

    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let cancellation = TestCancellation::pending();
    fake.cancel_after(3, &cancellation);
    let cancelled = provider
        .create(&spec, &cancellation)
        .expect_err("cancellation before readiness polling must be uncertain");
    assert_error(
        &cancelled,
        ProviderErrorKind::Cancelled,
        ProviderStage::CreateSandbox,
        OperationOutcome::Uncertain,
    );
    assert_eq!(cancelled.recovery_handle(), Some(&sandbox_handle(&spec)));
    assert_eq!(fake.request_count(), 4);

    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let cancellation = TestCancellation::pending();
    fake.cancel_after(4, &cancellation);
    let cancelled = provider
        .create(&spec, &cancellation)
        .expect_err("cancellation after readiness must be uncertain");
    assert_error(
        &cancelled,
        ProviderErrorKind::Cancelled,
        ProviderStage::Start,
        OperationOutcome::Uncertain,
    );
    assert_eq!(cancelled.recovery_handle(), Some(&sandbox_handle(&spec)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inspection_and_attachment_reject_malformed_stale_and_missing_pods() {
    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let spec = sandbox_spec();
    let handle = sandbox_handle(&spec);
    provider
        .create(&spec, &NeverCancelled)
        .expect("seed owned Pod");

    fake.override_next(StatusCode::OK, b"not-json".to_vec());
    let malformed = provider
        .inspect(&handle, &NeverCancelled)
        .expect_err("malformed API response must fail closed");
    assert_eq!(malformed.kind(), ProviderErrorKind::AdapterUnavailable);

    fake.set_pod_view(PodView::MalformedGeneration);
    let malformed = provider
        .inspect(&handle, &NeverCancelled)
        .expect_err("malformed identity must reject inspection");
    assert_eq!(malformed.kind(), ProviderErrorKind::OwnershipMismatch);

    fake.set_pod_view(PodView::Stopped);
    let stopped = provider
        .attach(&handle, &NeverCancelled)
        .expect_err("stopped Pod cannot attach");
    assert_eq!(stopped.kind(), ProviderErrorKind::InvalidState);

    fake.set_pod_view(PodView::MissingUid);
    let missing_uid = provider
        .attach(&handle, &NeverCancelled)
        .expect_err("UID-less Pod cannot attach");
    assert_eq!(missing_uid.kind(), ProviderErrorKind::BackendRejected);

    let foreign = SandboxHandle::new(
        ProviderId::new("another-provider").expect("provider id"),
        sandbox_name(&spec),
    )
    .expect("foreign handle");
    let before = fake.request_count();
    let foreign = provider
        .inspect(&foreign, &NeverCancelled)
        .expect_err("foreign handle must fail before API access");
    assert_eq!(foreign.kind(), ProviderErrorKind::OwnershipMismatch);
    assert_eq!(fake.request_count(), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_refuses_stale_generation_and_finishes_cleanup_after_late_cancellation() {
    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let spec = sandbox_spec();
    provider
        .create(&spec, &NeverCancelled)
        .expect("seed owned resources");
    fake.set_pod_view(PodView::MalformedGeneration);
    let stale = provider
        .destroy(&destroy_request(&spec), &NeverCancelled)
        .expect_err("stale generation must not be deleted");
    assert_error(
        &stale,
        ProviderErrorKind::OwnershipMismatch,
        ProviderStage::DestroySandbox,
        OperationOutcome::Uncertain,
    );
    assert_eq!(stale.recovery_handle(), Some(&sandbox_handle(&spec)));
    assert_eq!(fake.requests().last().expect("request").method, Method::GET);

    fake.set_pod_view(PodView::Running);
    let cancellation = TestCancellation::pending();
    fake.cancel_after(fake.request_count() + 3, &cancellation);
    let request = destroy_request(&spec);
    let destroyed = provider
        .destroy(&request, &cancellation)
        .expect("cleanup already in progress must preserve isolation through completion");
    assert_eq!(destroyed, DestroyDisposition::Destroyed);

    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let cancellation = TestCancellation::pending();
    fake.cancel_after(1, &cancellation);
    let absent = provider
        .destroy(&destroy_request(&spec), &cancellation)
        .expect("confirmed absence wins over cancellation observed after the checks");
    assert_eq!(absent, DestroyDisposition::AlreadyAbsent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadlines_api_errors_and_pre_cancelled_calls_map_to_bounded_failures() {
    let spec = sandbox_spec();
    let fake = FakeKube::default();
    let provider = test_provider(&fake);
    let cancelled = provider
        .create(&spec, &TestCancellation::cancelled())
        .expect_err("pre-cancelled create");
    assert_error(
        &cancelled,
        ProviderErrorKind::Cancelled,
        ProviderStage::Validate,
        OperationOutcome::KnownNoEffect,
    );
    let cancelled_destroy = provider
        .destroy(&destroy_request(&spec), &TestCancellation::cancelled())
        .expect_err("pre-cancelled destroy");
    assert_error(
        &cancelled_destroy,
        ProviderErrorKind::Cancelled,
        ProviderStage::DestroySandbox,
        OperationOutcome::KnownNoEffect,
    );
    assert_eq!(cancelled_destroy.recovery_handle(), None);
    assert!(fake.requests().is_empty());

    fake.override_next(StatusCode::FORBIDDEN, api_error(StatusCode::FORBIDDEN).1);
    let forbidden = provider
        .inspect(&sandbox_handle(&spec), &NeverCancelled)
        .expect_err("forbidden API request");
    assert_eq!(forbidden.kind(), ProviderErrorKind::InvalidConfiguration);

    let timeout_config = config()
        .with_timeouts(Duration::from_millis(5), Duration::from_secs(1))
        .expect("short deterministic timeout");
    let fake = FakeKube::default();
    fake.delay_next(Duration::from_secs(1));
    let provider = KubernetesSandboxProvider::new(fake.client(), timeout_config).expect("provider");
    let timed_out = provider
        .inspect(&sandbox_handle(&spec), &NeverCancelled)
        .expect_err("bounded API timeout");
    assert_eq!(timed_out.kind(), ProviderErrorKind::TimedOut);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_rejects_terminal_pods_and_bounds_readiness_waiting() {
    let spec = sandbox_spec();
    let fake = FakeKube::default();
    fake.set_pod_view(PodView::Stopped);
    let provider = test_provider(&fake);
    let stopped = provider
        .create(&spec, &NeverCancelled)
        .expect_err("terminal Pod cannot become ready");
    assert_error(
        &stopped,
        ProviderErrorKind::InvalidState,
        ProviderStage::CreateSandbox,
        OperationOutcome::Uncertain,
    );
    assert_eq!(stopped.recovery_handle(), Some(&sandbox_handle(&spec)));

    let fake = FakeKube::default();
    fake.set_pod_view(PodView::Pending);
    let config = config()
        .with_timeouts(Duration::from_secs(1), Duration::from_millis(5))
        .expect("bounded readiness timeout");
    let provider = KubernetesSandboxProvider::new(fake.client(), config).expect("provider");
    let timed_out = provider
        .create(&spec, &NeverCancelled)
        .expect_err("Pending Pod must not wait forever");
    assert_error(
        &timed_out,
        ProviderErrorKind::TimedOut,
        ProviderStage::CreateSandbox,
        OperationOutcome::Uncertain,
    );
    assert_eq!(timed_out.recovery_handle(), Some(&sandbox_handle(&spec)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kubernetes_api_statuses_map_to_stable_provider_failures() {
    let spec = sandbox_spec();
    let handle = sandbox_handle(&spec);
    for (status, expected) in [
        (StatusCode::NOT_FOUND, ProviderErrorKind::NotFound),
        (StatusCode::BAD_REQUEST, ProviderErrorKind::BackendRejected),
        (
            StatusCode::FORBIDDEN,
            ProviderErrorKind::InvalidConfiguration,
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            ProviderErrorKind::AdapterUnavailable,
        ),
    ] {
        let fake = FakeKube::default();
        fake.override_next(status, api_error(status).1);
        let error = test_provider(&fake)
            .attach(&handle, &NeverCancelled)
            .expect_err("scripted API status must reject attach");
        assert_error(
            &error,
            expected,
            ProviderStage::Attach,
            OperationOutcome::KnownNoEffect,
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capabilities_include_only_cluster_enforcement_that_was_attested() {
    let basic_config = KubernetesSandboxConfig::new(
        NAMESPACE,
        immutable_image("registry.example/automata/guest", 1),
        VerifiedNetworkIsolation,
    )
    .expect("basic config");
    let basic = KubernetesSandboxProvider::new(FakeKube::default().client(), basic_config)
        .expect("basic provider");
    for capability in [
        SandboxCapability::EphemeralStorageLimits,
        SandboxCapability::DeviceLimits,
        SandboxCapability::ProcessLimits,
    ] {
        assert!(!basic.capabilities().supports(capability));
    }

    let attested = test_provider(&FakeKube::default());
    for capability in [
        SandboxCapability::EphemeralStorageLimits,
        SandboxCapability::DeviceLimits,
        SandboxCapability::ProcessLimits,
    ] {
        assert!(attested.capabilities().supports(capability));
    }
    assert_eq!(attested.provider_id().as_str(), KUBERNETES_PROVIDER_ID);
    let debug = format!("{attested:?}");
    assert!(debug.contains(NAMESPACE));
    assert!(!debug.contains("registry.example"));
}
