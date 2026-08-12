use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_ci_auth::{
    human::{PrincipalId, TenantId},
    management::{ManagementActor, ManagementRequestId, ManagementRevision},
    session::SessionId,
    time::UnixTimestamp,
};
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, ImmutableBlobStore as _, MediaType, MemoryBlobStore,
};
use automata_ci_core::{OperationId, WorkflowId};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun,
    AuthenticatedGithubDeliveryClaim, AuthenticatedWorkflowDispatchClaim,
    AuthenticatedWorkflowDispatchSource, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError, ObjectKey,
    ResolveAuthenticatedWorkflowDispatchSource, TenantScope, WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_github::{
    GithubWorkflowDispatchInputValue, GithubWorkflowDispatchInputsV1,
};
use automata_ci_workflow_service::{
    AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE, AdmissionIdGenerator,
    AdmissionRepositoryCoordinates, DurableGithubWorkflowDispatchRequest,
    GITHUB_WORKFLOW_MEDIA_TYPE, GithubWorkflowDispatchError, GithubWorkflowDispatchRequest,
    GithubWorkflowDispatchService, GithubWorkflowPlanVerifier, Sha256AdmissionIdGenerator,
    WorkflowAdmissionError, WorkflowAdmissionService, WorkflowDispatchAuthorization,
};
use bytes::Bytes;
use uuid::Uuid;

const TENANT: &str = "tenant-synthetic-dispatch";
const PRINCIPAL: &str = "550e8400-e29b-41d4-a716-446655440010";
const SESSION: &str = "550e8400-e29b-41d4-a716-446655440011";
const WORKFLOW_PATH: &str = ".ci/workflows/manual.yml";
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const GIT_REF: &str = "refs/heads/release";
const SOURCE: &str = r"name: Synthetic manual dispatch
on:
  workflow_dispatch:
    inputs:
      target:
        description: Deployment target
        required: true
        type: choice
        options: [test, live]
      dry_run:
        type: boolean
        default: false
      note:
        type: string
        default: ready
jobs:
  verify:
    runs-on: linux
    steps:
      - run: echo synthetic
";

#[tokio::test]
async fn dispatch_request_debug_omits_private_source_and_subject_data() {
    let harness = Harness::new();
    let operation_id = OperationId::from_uuid(Uuid::from_u128(0x99));
    let request = harness.request(operation_id, "live", true, "private input marker");
    let debug = format!("{request:?}");
    for private_value in [
        TENANT,
        PRINCIPAL,
        SESSION,
        WORKFLOW_PATH,
        COMMIT_SHA,
        GIT_REF,
        "neutral-fixture",
        "private input marker",
        "echo synthetic",
    ] {
        assert!(
            !debug.contains(private_value),
            "Debug leaked {private_value}"
        );
    }
    assert!(debug.contains("source_size_bytes"));
    assert!(debug.contains("input_count"));

    let authorization =
        WorkflowDispatchAuthorization::new(actor(), harness.repository_id, harness.workflow_id)
            .expect("synthetic authority");
    let authorization_debug = format!("{authorization:?}");
    assert!(!authorization_debug.contains(TENANT));
    assert!(!authorization_debug.contains(PRINCIPAL));
    assert!(!authorization_debug.contains(SESSION));

    let lookup = ResolveAuthenticatedWorkflowDispatchSource::new(
        actor(),
        harness.repository_id,
        harness.workflow_id,
        GIT_REF,
        COMMIT_SHA,
    )
    .expect("exact source lookup");
    let lookup_debug = format!("{lookup:?}");
    assert!(!lookup_debug.contains(TENANT));
    assert!(!lookup_debug.contains(PRINCIPAL));
    assert!(!lookup_debug.contains(SESSION));
    assert!(!lookup_debug.contains(GIT_REF));
    assert!(!lookup_debug.contains(COMMIT_SHA));

    let inputs = GithubWorkflowDispatchInputsV1::try_new([(
        "note",
        GithubWorkflowDispatchInputValue::from("durable private marker"),
    )])
    .expect("bounded dispatch inputs");
    let durable = DurableGithubWorkflowDispatchRequest::new(
        authorization,
        GIT_REF,
        COMMIT_SHA,
        inputs,
        operation_id,
    );
    let debug = format!("{durable:?}");
    assert!(!debug.contains(GIT_REF));
    assert!(!debug.contains(COMMIT_SHA));
    assert!(!debug.contains("durable private marker"));
    assert!(debug.contains("input_count"));

    harness.seed_durable_source().await;
    let source_debug = {
        let state = harness.repository.state.lock().expect("state lock");
        format!("{:?}", state.source.as_ref().expect("durable source"))
    };
    assert!(!source_debug.contains("neutral-fixture"));
    assert!(!source_debug.contains(WORKFLOW_PATH));
    assert!(!source_debug.contains(GIT_REF));
    assert!(!source_debug.contains(COMMIT_SHA));
}

#[tokio::test]
async fn authenticated_dispatch_binds_typed_inputs_and_exact_replay() {
    let operation_id = OperationId::from_uuid(Uuid::from_u128(0x100));
    let harness = Harness::new();
    let request = harness.request(operation_id, "live", true, "operator supplied");

    let first = Box::pin(harness.service.dispatch(request.clone()))
        .await
        .expect("first authenticated dispatch");
    assert!(!first.receipt().is_replay());

    let replay = Box::pin(harness.service.dispatch(request))
        .await
        .expect("exact authenticated replay");
    assert!(replay.receipt().is_replay());
    assert_eq!(replay.receipt().run_id(), first.receipt().run_id());

    let attempts = harness.repository.attempts();
    assert_eq!(attempts.len(), 2);
    let (first_command, first_claim) = &attempts[0];
    let (replayed_command, replayed_claim) = &attempts[1];
    assert_eq!(
        first_command.request_digest(),
        replayed_command.request_digest()
    );
    assert_eq!(first_claim, replayed_claim);
    assert_eq!(first_command.event_name(), "workflow_dispatch");
    assert_eq!(
        first_command.event().media_type(),
        AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE
    );
    assert_eq!(first_claim.event_digest(), first_command.event().digest());
    assert_eq!(
        first_claim.base_context_digest(),
        first_command
            .base_context()
            .expect("dispatch base context")
            .digest()
    );
    assert_eq!(first_claim.repository_id(), first_command.repository().id());
    assert_eq!(first_claim.workflow_id(), first_command.workflow_id());
    assert_eq!(first_claim.workflow_path(), WORKFLOW_PATH);
    assert_eq!(first_claim.git_ref(), GIT_REF);
    assert_eq!(first_claim.operation_id(), operation_id);
    let claim_debug = format!("{first_claim:?}");
    assert!(!claim_debug.contains(TENANT));
    assert!(!claim_debug.contains(PRINCIPAL));
    assert!(!claim_debug.contains(SESSION));
    assert!(!claim_debug.contains(WORKFLOW_PATH));
    assert!(!claim_debug.contains(GIT_REF));

    let evidence = harness.load(first_command.event()).await;
    let evidence: serde_json::Value =
        serde_json::from_slice(&evidence).expect("canonical dispatch evidence JSON");
    assert_eq!(evidence["kind"], "automata_workflow_dispatch");
    assert_eq!(evidence["inputs"]["target"], "live");
    assert_eq!(evidence["inputs"]["dry_run"], true);
    assert_eq!(evidence["inputs"]["note"], "operator supplied");

    let base_context = harness
        .load(
            first_command
                .base_context()
                .expect("dispatch base context descriptor"),
        )
        .await;
    let base_context = automata_ci_protocol_protobuf::decode_job_runtime_context(
        &base_context,
        &ProtocolLimits::default(),
    )
    .expect("canonical base context");
    let inputs = base_context.inputs().as_object().expect("inputs object");
    assert_eq!(inputs["target"].as_string(), Some("live"));
    assert_eq!(inputs["dry_run"].as_boolean(), Some(true));
    assert_eq!(inputs["note"].as_string(), Some("operator supplied"));

    let error = Box::pin(harness.service.dispatch(harness.request(
        operation_id,
        "test",
        false,
        "tampered replay",
    )))
    .await
    .expect_err("changed evidence under one operation must conflict");
    assert!(matches!(
        error,
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::IdempotencyConflict
        ))
    ));
    let attempts = harness.repository.attempts();
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0].0.run_id(), attempts[2].0.run_id());
    assert_ne!(
        attempts[0].0.request_digest(),
        attempts[2].0.request_digest()
    );
    harness.repository.assert_only_dispatch_path(3);
}

#[tokio::test]
async fn mismatched_durable_workflow_target_fails_before_store_admission() {
    let harness = Harness::new();
    let wrong_workflow_id = WorkflowId::from_uuid(Uuid::from_u128(0xdead));
    let authorization =
        WorkflowDispatchAuthorization::new(actor(), harness.repository_id, wrong_workflow_id)
            .expect("synthetic authority");
    let request = dispatch_request(
        authorization,
        harness.coordinates.clone(),
        OperationId::from_uuid(Uuid::from_u128(0x101)),
        "live",
        true,
        "exact target",
    );

    let error = Box::pin(harness.service.dispatch(request))
        .await
        .expect_err("derived workflow identity must match authenticated target");
    assert!(matches!(
        error,
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::WorkflowDispatchEvidence)
    ));
    harness.repository.assert_only_dispatch_path(0);
}

#[tokio::test]
async fn product_dispatch_loads_only_an_exact_signed_durable_source() {
    let harness = Harness::new();
    harness.seed_durable_source().await;
    let inputs = GithubWorkflowDispatchInputsV1::try_new([
        ("target", GithubWorkflowDispatchInputValue::from("test")),
        ("dry_run", GithubWorkflowDispatchInputValue::Boolean(false)),
        (
            "note",
            GithubWorkflowDispatchInputValue::from("durable source"),
        ),
    ])
    .expect("bounded inputs");
    let request = DurableGithubWorkflowDispatchRequest::new(
        WorkflowDispatchAuthorization::new(actor(), harness.repository_id, harness.workflow_id)
            .expect("exact authority"),
        GIT_REF,
        COMMIT_SHA,
        inputs.clone(),
        OperationId::from_uuid(Uuid::from_u128(0x102)),
    );
    let admitted = harness
        .service
        .dispatch_from_durable_source(request)
        .await
        .expect("durable source dispatch");
    assert!(!admitted.receipt().is_replay());
    assert_eq!(harness.repository.source_calls.load(Ordering::SeqCst), 1);
    harness.repository.assert_only_dispatch_path(1);

    let missing = DurableGithubWorkflowDispatchRequest::new(
        WorkflowDispatchAuthorization::new(actor(), harness.repository_id, harness.workflow_id)
            .expect("exact authority"),
        GIT_REF,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        inputs,
        OperationId::from_uuid(Uuid::from_u128(0x103)),
    );
    assert!(matches!(
        harness.service.dispatch_from_durable_source(missing).await,
        Err(GithubWorkflowDispatchError::DurableSourceNotFound)
    ));
    assert_eq!(harness.repository.source_calls.load(Ordering::SeqCst), 2);
    harness.repository.assert_only_dispatch_path(1);
}

#[tokio::test]
async fn malformed_or_non_branch_tag_refs_fail_before_source_lookup() {
    let harness = Harness::new();
    for (index, git_ref) in [
        "refs/heads/has space",
        "refs/heads/two..dots",
        "refs/heads/name@{one}",
        "refs/heads/double//slash",
        "refs/heads/.hidden",
        "refs/heads/topic.lock",
        "refs/pull/17/merge",
    ]
    .into_iter()
    .enumerate()
    {
        let request = DurableGithubWorkflowDispatchRequest::new(
            WorkflowDispatchAuthorization::new(actor(), harness.repository_id, harness.workflow_id)
                .expect("exact authority"),
            git_ref,
            COMMIT_SHA,
            GithubWorkflowDispatchInputsV1::try_new(Vec::<(
                String,
                GithubWorkflowDispatchInputValue,
            )>::new())
            .expect("empty inputs"),
            OperationId::from_uuid(Uuid::from_u128(0x200 + index as u128)),
        );
        assert!(matches!(
            harness.service.dispatch_from_durable_source(request).await,
            Err(GithubWorkflowDispatchError::Request(_))
        ));
    }
    assert_eq!(harness.repository.source_calls.load(Ordering::SeqCst), 0);
    harness.repository.assert_only_dispatch_path(0);
}

struct Harness {
    service: GithubWorkflowDispatchService,
    blobs: MemoryBlobStore,
    repository: Arc<DispatchRepository>,
    coordinates: AdmissionRepositoryCoordinates,
    repository_id: automata_ci_store::RepositoryId,
    workflow_id: WorkflowId,
}

impl Harness {
    fn new() -> Self {
        let coordinates = coordinates();
        let tenant = TenantScope::from_authenticated_tenant_id(TENANT).expect("tenant scope");
        let ids = Sha256AdmissionIdGenerator;
        let repository_id = ids.repository_id(&tenant, &coordinates);
        let workflow_id = ids.workflow_id(repository_id, WORKFLOW_PATH);
        let blobs = MemoryBlobStore::default();
        let repository = Arc::new(DispatchRepository::default());
        let admission = WorkflowAdmissionService::with_system_ports(
            Arc::new(blobs.clone()),
            repository.clone(),
            Arc::new(GithubWorkflowPlanVerifier::new()),
        );
        Self {
            service: GithubWorkflowDispatchService::new(admission),
            blobs,
            repository,
            coordinates,
            repository_id,
            workflow_id,
        }
    }

    fn request(
        &self,
        operation_id: OperationId,
        target: &str,
        dry_run: bool,
        note: &str,
    ) -> GithubWorkflowDispatchRequest {
        let authorization =
            WorkflowDispatchAuthorization::new(actor(), self.repository_id, self.workflow_id)
                .expect("synthetic authority");
        dispatch_request(
            authorization,
            self.coordinates.clone(),
            operation_id,
            target,
            dry_run,
            note,
        )
    }

    async fn load(&self, object: &automata_ci_store::AdmissionObject) -> Bytes {
        let descriptor = BlobDescriptor::new(
            BlobKey::new(object.object_key().as_str()).expect("blob key"),
            object.digest(),
            object.encoded_size(),
            MediaType::new(object.media_type()).expect("media type"),
        );
        self.blobs
            .get_verified(&descriptor, object.encoded_size())
            .await
            .expect("published admission object")
            .into_bytes()
    }

    async fn seed_durable_source(&self) {
        let key = BlobKey::new("dispatch-test/signed-source").expect("source key");
        let payload = BlobPayload::from_bytes(
            key,
            MediaType::new(GITHUB_WORKFLOW_MEDIA_TYPE).expect("source media type"),
            Bytes::from_static(SOURCE.as_bytes()),
        );
        let descriptor = payload.descriptor().clone();
        self.blobs
            .put_if_absent(payload)
            .await
            .expect("publish signed source fixture");
        let source = AdmissionObject::new(
            descriptor.digest(),
            ObjectKey::new(descriptor.key().as_str()).expect("object key"),
            descriptor.size(),
            descriptor.media_type().as_str(),
        )
        .expect("source descriptor");
        let repository = AdmissionRepository::new(
            self.repository_id,
            self.coordinates.provider(),
            self.coordinates.provider_repository_id(),
            self.coordinates.owner(),
            self.coordinates.name(),
        )
        .expect("repository descriptor");
        let source = AuthenticatedWorkflowDispatchSource::new(
            repository,
            self.workflow_id,
            WORKFLOW_PATH,
            GIT_REF,
            COMMIT_SHA,
            source,
        )
        .expect("signed source fixture");
        self.repository.state.lock().expect("state lock").source = Some(source);
    }
}

fn coordinates() -> AdmissionRepositoryCoordinates {
    AdmissionRepositoryCoordinates::new(
        "github",
        "synthetic-repository-42",
        "automata-ci",
        "neutral-fixture",
    )
    .expect("repository coordinates")
}

fn actor() -> ManagementActor {
    ManagementActor::new(
        TenantId::new(TENANT).expect("tenant"),
        PrincipalId::new(PRINCIPAL).expect("principal"),
        SessionId::new(SESSION).expect("session"),
        ManagementRevision::new(7).expect("authorization revision"),
        Some(ManagementRequestId::new("synthetic-dispatch-request").expect("request ID")),
        UnixTimestamp::from_seconds(1_800_000_000),
    )
}

fn dispatch_request(
    authorization: WorkflowDispatchAuthorization,
    coordinates: AdmissionRepositoryCoordinates,
    operation_id: OperationId,
    target: &str,
    dry_run: bool,
    note: &str,
) -> GithubWorkflowDispatchRequest {
    let inputs = GithubWorkflowDispatchInputsV1::try_new([
        (
            "target",
            GithubWorkflowDispatchInputValue::String(target.to_owned()),
        ),
        (
            "dry_run",
            GithubWorkflowDispatchInputValue::Boolean(dry_run),
        ),
        (
            "note",
            GithubWorkflowDispatchInputValue::String(note.to_owned()),
        ),
    ])
    .expect("bounded dispatch inputs");
    GithubWorkflowDispatchRequest::new(
        authorization,
        coordinates,
        WORKFLOW_PATH,
        Bytes::from_static(SOURCE.as_bytes()),
        COMMIT_SHA,
        GIT_REF,
        inputs,
        operation_id,
    )
    .with_workflow_name("Synthetic manual dispatch")
}

#[derive(Debug, Default)]
struct DispatchRepository {
    state: Mutex<DispatchState>,
    generic_calls: AtomicUsize,
    github_calls: AtomicUsize,
    dispatch_calls: AtomicUsize,
    source_calls: AtomicUsize,
}

#[derive(Debug, Default)]
struct DispatchState {
    source: Option<AuthenticatedWorkflowDispatchSource>,
    durable: Option<DurableDispatch>,
    attempts: Vec<(AdmitLogicalWorkflowRun, AuthenticatedWorkflowDispatchClaim)>,
}

#[derive(Debug)]
struct DurableDispatch {
    request_digest: automata_ci_core::Sha256Digest,
    claim: AuthenticatedWorkflowDispatchClaim,
    receipt: LogicalWorkflowAdmissionReceipt,
}

impl DispatchRepository {
    fn attempts(&self) -> Vec<(AdmitLogicalWorkflowRun, AuthenticatedWorkflowDispatchClaim)> {
        self.state.lock().expect("state lock").attempts.clone()
    }

    fn assert_only_dispatch_path(&self, expected_dispatch_calls: usize) {
        assert_eq!(self.generic_calls.load(Ordering::SeqCst), 0);
        assert_eq!(self.github_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            self.dispatch_calls.load(Ordering::SeqCst),
            expected_dispatch_calls
        );
    }
}

#[async_trait]
impl LogicalWorkflowAdmissionRepository for DispatchRepository {
    async fn resolve_authenticated_workflow_dispatch_source(
        &self,
        request: ResolveAuthenticatedWorkflowDispatchSource,
    ) -> Result<Option<AuthenticatedWorkflowDispatchSource>, LogicalWorkflowAdmissionStoreError>
    {
        self.source_calls.fetch_add(1, Ordering::SeqCst);
        let source = self.state.lock().expect("state lock").source.clone();
        Ok(source.filter(|source| {
            request.actor() == &actor()
                && request.repository_id() == source.repository().id()
                && request.workflow_id() == source.workflow_id()
                && request.git_ref() == source.git_ref()
                && request.commit_sha() == source.commit_sha()
        }))
    }

    async fn admit_logical_workflow(
        &self,
        _command: AdmitLogicalWorkflowRun,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        self.generic_calls.fetch_add(1, Ordering::SeqCst);
        Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
    }

    async fn admit_authenticated_github_delivery(
        &self,
        _command: AdmitLogicalWorkflowRun,
        _current_claim: AuthenticatedGithubDeliveryClaim,
        _observed_at: automata_ci_core::UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        self.github_calls.fetch_add(1, Ordering::SeqCst);
        Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
    }

    async fn admit_authenticated_workflow_dispatch(
        &self,
        command: AdmitLogicalWorkflowRun,
        claim: AuthenticatedWorkflowDispatchClaim,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        self.dispatch_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(claim.repository_id(), command.repository().id());
        assert_eq!(claim.workflow_id(), command.workflow_id());
        assert_eq!(claim.workflow_path(), command.workflow_path());
        assert_eq!(claim.git_ref(), command.git_ref());
        assert_eq!(claim.event_digest(), command.event().digest());
        assert_eq!(
            Some(claim.base_context_digest()),
            command
                .base_context()
                .map(automata_ci_store::AdmissionObject::digest)
        );
        assert!(matches!(
            command.idempotency(),
            WorkflowAdmissionIdempotency::Operation(operation_id)
                if *operation_id == claim.operation_id()
        ));

        let mut state = self.state.lock().expect("state lock");
        state.attempts.push((command.clone(), claim.clone()));
        if let Some(durable) = &state.durable {
            if durable.request_digest != command.request_digest() || durable.claim != claim {
                return Err(LogicalWorkflowAdmissionStoreError::IdempotencyConflict);
            }
            let prior = durable.receipt;
            return Ok(LogicalWorkflowAdmissionReceipt::new(
                prior.repository_id(),
                prior.workflow_id(),
                prior.snapshot_id(),
                prior.run_id(),
                prior.root_invocation_id(),
                prior.run_number(),
                true,
            ));
        }

        let receipt = LogicalWorkflowAdmissionReceipt::new(
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            command.root_invocation_id(),
            1,
            false,
        );
        state.durable = Some(DurableDispatch {
            request_digest: command.request_digest(),
            claim,
            receipt,
        });
        Ok(receipt)
    }
}
