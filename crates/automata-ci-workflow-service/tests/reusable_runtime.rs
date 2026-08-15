use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, ImmutableBlobStore as _, MediaType, MemoryBlobStore,
};
use automata_ci_core::{
    ContextValue, JobAuthorityProfile, JobRuntimeContext, LogicalResultValue, OutputSensitivity,
    PermissionLevel, RunId, RunIdAlias, SecretBinding, Sha256Digest, UnixMillis,
    WorkflowEventProvenance, WorkflowId, WorkflowJobKey,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    AdmissionObject, AdmittedReusableInputKind, CompleteReusableWorkflowCall,
    LogicalActivationBaseContextKind, LogicalActivationExecutionContext,
    LogicalActivationPreparationDescriptor, LogicalActivationPreparationTarget,
    LogicalWorkflowInvocationId, ObjectKey, PinnedWorkflowRuntimePolicy,
    PublishReusableWorkflowCall, ReadyReusableWorkflowCall, ReadyReusableWorkflowCompletion,
    RepositoryId, ReusableWorkflowCompletionReceipt, ReusableWorkflowInputBindingEvidence,
    ReusableWorkflowPermissionSnapshot, ReusableWorkflowPublicationReceipt,
    ReusableWorkflowResultOutput, ReusableWorkflowRuntimeRepository,
    ReusableWorkflowRuntimeStoreError, ReusableWorkflowSecretBindingEvidence, TenantScope,
    WorkflowRuntimePolicy, WorkflowRuntimePolicyPin, WorkflowRuntimePolicyRevision,
};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use automata_ci_workflow_service::{
    ExpandReusableWorkflowRequest, GITHUB_RUNNER_POLICY_MEDIA_TYPE, GithubReusableWorkflowCatalog,
    GithubReusableWorkflowSourceAuthority, JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
    RepositoryWorkflowSource, ReusableInputBindingSource, ReusableWorkflowExpander,
    ReusableWorkflowPermissions, ReusableWorkflowRuntimeOutcome, ReusableWorkflowRuntimeService,
    WORKFLOW_EVENT_MEDIA_TYPE, WORKFLOW_PLAN_MEDIA_TYPE,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const REPOSITORY: &str = "synthetic/runtime";
const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const ROOT_PATH: &str = ".ci/workflows/root.yml";
const CHILD_PATH: &str = ".ci/workflows/child.yml";
const GIT_REF: &str = "refs/heads/main";

const ROOT: &str = r"name: Root
on: workflow_dispatch
permissions: write-all
jobs:
  invoke:
    permissions:
      contents: read
    uses: ./.ci/workflows/child.yml
    with:
      enabled: true
    secrets:
      token: ${{ secrets.ROOT_TOKEN }}
  consume:
    needs: invoke
    runs-on: linux
    steps:
      - run: echo ${{ needs.invoke.outputs.digest }}
";

const CHILD: &str = r"name: Child
on:
  workflow_call:
    inputs:
      enabled:
        required: true
        type: boolean
      attempts:
        type: number
        default: 2
      channel:
        type: string
        default: stable
    secrets:
      token:
        required: true
    outputs:
      digest:
        value: ${{ jobs.build.outputs.digest }}
permissions:
  contents: write
jobs:
  build:
    runs-on: linux
    outputs:
      digest: ${{ steps.result.outputs.digest }}
    steps:
      - id: result
        run: echo digest=synthetic
";

const INHERITED_ROOT: &str = r"name: Root
on: workflow_dispatch
jobs:
  invoke:
    uses: ./.ci/workflows/child.yml
    secrets: inherit
";

const INHERITED_CHILD: &str = r#"name: Child
on:
  workflow_call: {}
jobs:
  consume:
    runs-on: linux
    steps:
      - run: echo "${{ secrets.UNDECLARED_TOKEN }}"
"#;

const RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":[],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a","id":"github/ubuntu-24-04"},
    "selector":"ubuntu-latest"
  }],"permissions":{"provider_default":{"contents":"read","packages":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

#[derive(Debug, Default)]
struct RepositoryState {
    calls: VecDeque<ReadyReusableWorkflowCall>,
    completions: VecDeque<ReadyReusableWorkflowCompletion>,
    publications: Vec<PublishReusableWorkflowCall>,
    results: Vec<CompleteReusableWorkflowCall>,
}

#[derive(Debug, Default)]
struct RuntimeRepository {
    state: Mutex<RepositoryState>,
}

impl RuntimeRepository {
    fn push_call(&self, call: ReadyReusableWorkflowCall) {
        self.state
            .lock()
            .expect("repository lock")
            .calls
            .push_back(call);
    }

    fn push_completion(&self, completion: ReadyReusableWorkflowCompletion) {
        self.state
            .lock()
            .expect("repository lock")
            .completions
            .push_back(completion);
    }

    fn publication(&self) -> PublishReusableWorkflowCall {
        self.state.lock().expect("repository lock").publications[0].clone()
    }

    fn results(&self) -> Vec<CompleteReusableWorkflowCall> {
        self.state.lock().expect("repository lock").results.clone()
    }
}

#[async_trait]
impl ReusableWorkflowRuntimeRepository for RuntimeRepository {
    async fn next_reusable_workflow_call(
        &self,
    ) -> Result<Option<ReadyReusableWorkflowCall>, ReusableWorkflowRuntimeStoreError> {
        Ok(self
            .state
            .lock()
            .expect("repository lock")
            .calls
            .pop_front())
    }

    async fn next_reusable_workflow_completion(
        &self,
    ) -> Result<Option<ReadyReusableWorkflowCompletion>, ReusableWorkflowRuntimeStoreError> {
        Ok(self
            .state
            .lock()
            .expect("repository lock")
            .completions
            .pop_front())
    }

    async fn publish_reusable_workflow_call(
        &self,
        request: PublishReusableWorkflowCall,
    ) -> Result<ReusableWorkflowPublicationReceipt, ReusableWorkflowRuntimeStoreError> {
        let mut state = self.state.lock().expect("repository lock");
        match state.publications.first() {
            Some(existing) if existing == &request => {
                Ok(ReusableWorkflowPublicationReceipt::new(&request, true))
            }
            Some(_) => Err(ReusableWorkflowRuntimeStoreError::Conflict),
            None => {
                state.publications.push(request.clone());
                Ok(ReusableWorkflowPublicationReceipt::new(&request, false))
            }
        }
    }

    async fn complete_reusable_workflow_call(
        &self,
        request: CompleteReusableWorkflowCall,
    ) -> Result<ReusableWorkflowCompletionReceipt, ReusableWorkflowRuntimeStoreError> {
        let mut state = self.state.lock().expect("repository lock");
        match state.results.first() {
            Some(existing) if existing == &request => {
                Ok(ReusableWorkflowCompletionReceipt::new(&request, true))
            }
            Some(_) => Err(ReusableWorkflowRuntimeStoreError::Conflict),
            None => {
                state.results.push(request.clone());
                Ok(ReusableWorkflowCompletionReceipt::new(&request, false))
            }
        }
    }
}

#[tokio::test]
async fn autonomous_runtime_publishes_typed_context_and_completes_exact_outputs_once() {
    let blobs = Arc::new(MemoryBlobStore::default());
    let repository = Arc::new(RuntimeRepository::default());
    let fixture = runtime_fixture(&blobs, ROOT, CHILD, "ROOT_TOKEN").await;
    repository.push_call(fixture.call);
    let service = ReusableWorkflowRuntimeService::new(repository.clone(), blobs.clone());
    let shutdown = CancellationToken::new();

    let publication = service.run_once(&shutdown).await.expect("publication");
    let ReusableWorkflowRuntimeOutcome::Published(receipt) = publication else {
        panic!("expected a publication, got {publication:?}");
    };
    assert!(!receipt.is_replay());
    let published = repository.publication();
    assert!(published.condition_matched());
    assert_eq!(published.output_mappings().len(), 1);
    assert_eq!(
        published.output_mappings()[0].parent_name().as_str(),
        "digest"
    );
    assert_eq!(
        published.output_mappings()[0].callee_name().as_str(),
        "digest"
    );

    let context = load_runtime_context(&blobs, published.runtime_context()).await;
    let inputs = context.inputs().as_object().expect("callee inputs");
    assert_eq!(inputs.get("enabled"), Some(&ContextValue::boolean(true)));
    assert_eq!(inputs.get("attempts"), Some(&ContextValue::number(2.0)));
    assert_eq!(inputs.get("channel"), Some(&ContextValue::string("stable")),);
    assert_eq!(context.secrets().get("token"), Some(&fixture.secret));
    assert!(!context.secrets().contains_key("ROOT_TOKEN"));

    let contract = fixture
        .child_plan
        .logical()
        .invocation()
        .expect("child invocation contract");
    let output = &contract.outputs()[0];
    let [reference] = output.references() else {
        panic!("compiler must retain one exact child result reference");
    };
    let LogicalResultValue::Output(output_name) = reference.value().value() else {
        panic!("workflow output must reference a child job output");
    };
    let public_value =
        (output.sensitivity() == OutputSensitivity::Public).then(|| "visible-digest".to_owned());
    let completion = ReadyReusableWorkflowCompletion::new(
        published,
        fixture.child_plan_object,
        vec![ReusableWorkflowResultOutput::new(
            reference.value().job().clone(),
            output_name.clone(),
            output.sensitivity(),
            public_value,
        )],
        UnixMillis::new(10),
    );
    repository.push_completion(completion.clone());

    let first = service.run_once(&shutdown).await.expect("completion");
    let ReusableWorkflowRuntimeOutcome::Completed(first_receipt) = first else {
        panic!("expected a completion, got {first:?}");
    };
    assert!(!first_receipt.is_replay());
    let results = repository.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].outputs().len(), 1);
    assert_eq!(results[0].outputs()[0].sensitivity(), output.sensitivity());
    assert_eq!(
        results[0].outputs()[0].public_value(),
        (output.sensitivity() == OutputSensitivity::Public).then_some("visible-digest"),
    );

    repository.push_completion(completion);
    let replay = service
        .run_once(&shutdown)
        .await
        .expect("completion replay");
    let ReusableWorkflowRuntimeOutcome::Completed(replay_receipt) = replay else {
        panic!("expected a completion replay, got {replay:?}");
    };
    assert!(replay_receipt.is_replay());
    assert_eq!(
        replay_receipt.outputs_digest(),
        first_receipt.outputs_digest()
    );
    assert_eq!(repository.results().len(), 1);
}

#[tokio::test]
async fn autonomous_runtime_materializes_an_undeclared_inherited_secret() {
    let blobs = Arc::new(MemoryBlobStore::default());
    let repository = Arc::new(RuntimeRepository::default());
    let fixture =
        runtime_fixture(&blobs, INHERITED_ROOT, INHERITED_CHILD, "UNDECLARED_TOKEN").await;
    assert!(
        fixture
            .child_plan
            .logical()
            .invocation()
            .expect("child invocation contract")
            .secrets()
            .is_empty(),
        "the regression must exercise a secret omitted from workflow_call.secrets",
    );
    repository.push_call(fixture.call);
    let service = ReusableWorkflowRuntimeService::new(repository.clone(), blobs.clone());

    let outcome = service
        .run_once(&CancellationToken::new())
        .await
        .expect("publication");
    assert!(matches!(
        outcome,
        ReusableWorkflowRuntimeOutcome::Published(_)
    ));
    let context = load_runtime_context(&blobs, repository.publication().runtime_context()).await;
    assert_eq!(context.secrets().len(), 1);
    assert_eq!(
        context.secrets().get("UNDECLARED_TOKEN"),
        Some(&fixture.secret),
    );
}

struct RuntimeFixture {
    call: ReadyReusableWorkflowCall,
    child_plan: automata_ci_core::WorkflowPlan,
    child_plan_object: AdmissionObject,
    secret: SecretBinding,
}

#[allow(clippy::too_many_lines)] // One fixture binds every object the autonomous boundary verifies.
async fn runtime_fixture(
    blobs: &MemoryBlobStore,
    root_source: &str,
    child_source: &str,
    available_secret_name: &str,
) -> RuntimeFixture {
    let run_id = RunId::from_uuid(Uuid::from_u128(11));
    let root_invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(12)).expect("root invocation");
    let root_plan = compile_root(root_source);
    let catalog = GithubReusableWorkflowCatalog::compile(
        GithubReusableWorkflowSourceAuthority::GithubDelivery,
        REPOSITORY,
        REVISION,
        [RepositoryWorkflowSource::new(
            CHILD_PATH,
            Bytes::copy_from_slice(child_source.as_bytes()),
        )],
    )
    .expect("child catalog");
    let child_plan = catalog
        .entries()
        .next()
        .expect("catalog entry")
        .plan()
        .clone();
    let root_permissions = ReusableWorkflowPermissions::new(PermissionLevel::Write, Vec::new())
        .expect("root permissions");
    let available_secrets = BTreeSet::from([available_secret_name.to_owned()]);
    let expansion = ReusableWorkflowExpander::new()
        .expand(ExpandReusableWorkflowRequest::new(
            run_id,
            root_invocation_id,
            ROOT_PATH,
            root_source.as_bytes(),
            &root_plan,
            &catalog,
            &available_secrets,
            &root_permissions,
        ))
        .expect("reusable expansion");
    let child = &expansion.invocations()[1];
    let caller_job_id = child.caller_job_id().expect("caller job");
    let repository_id = RepositoryId::from_uuid(Uuid::from_u128(16));
    let tenant = TenantScope::from_authenticated_tenant_id("synthetic-tenant").expect("tenant");
    let target = LogicalActivationPreparationTarget::new(
        tenant.clone(),
        run_id,
        root_invocation_id,
        caller_job_id,
    )
    .expect("preparation target");

    let plan_object = put_object(
        blobs,
        "runtime/root-plan.json",
        WORKFLOW_PLAN_MEDIA_TYPE,
        Bytes::from(serde_json::to_vec(&root_plan).expect("root plan JSON")),
    )
    .await;
    let child_plan_object = put_object(
        blobs,
        "runtime/child-plan.json",
        WORKFLOW_PLAN_MEDIA_TYPE,
        Bytes::from(serde_json::to_vec(&child_plan).expect("child plan JSON")),
    )
    .await;
    let event_object = put_object(
        blobs,
        "runtime/event.json",
        WORKFLOW_EVENT_MEDIA_TYPE,
        Bytes::from_static(br#"{"synthetic":true}"#),
    )
    .await;
    let secret = SecretBinding::new("binding/synthetic")
        .expect("secret binding")
        .with_version_id("version/synthetic")
        .expect("secret version");
    let base_context = JobRuntimeContext::new_base(
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        BTreeMap::from([(available_secret_name.to_owned(), secret.clone())]),
    )
    .expect("base context");
    let base_context_object = put_object(
        blobs,
        "runtime/base-context.pb",
        JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
        Bytes::from(
            automata_ci_protocol_protobuf::encode_job_runtime_context(
                &base_context,
                &ProtocolLimits::default(),
            )
            .expect("base context encoding"),
        ),
    )
    .await;
    let runtime_policy =
        WorkflowRuntimePolicy::decode_configuration(RUNTIME_POLICY).expect("runtime policy");
    let runner_policy_key = format!(
        "github/runner-policy/v1/{}.json",
        runtime_policy.canonical_digest(),
    );
    let runner_policy = put_object(
        blobs,
        &runner_policy_key,
        GITHUB_RUNNER_POLICY_MEDIA_TYPE,
        Bytes::from(
            runtime_policy
                .canonical_bytes()
                .expect("runtime policy bytes"),
        ),
    )
    .await;
    let pin = WorkflowRuntimePolicyPin::new(
        tenant,
        repository_id,
        WorkflowRuntimePolicyRevision::new(1).expect("policy revision"),
        runtime_policy.digest(),
    );
    let pinned =
        PinnedWorkflowRuntimePolicy::new(run_id, pin, runtime_policy).expect("pinned policy");
    let logical_key = WorkflowJobKey::new("invoke").expect("caller key");
    let source_order = u16::try_from(
        root_plan
            .job(&logical_key)
            .expect("caller job")
            .source_order(),
    )
    .expect("source order");
    let preparation = LogicalActivationPreparationDescriptor::new(
        target,
        logical_key,
        source_order,
        LogicalActivationExecutionContext::new(
            WorkflowId::from_uuid(Uuid::from_u128(17)),
            "Synthetic CI".to_owned(),
            GIT_REF.to_owned(),
            "push".to_owned(),
            Some("synthetic-actor".to_owned()),
            RunIdAlias::new(11).expect("run alias"),
            1,
            1,
        )
        .expect("execution context"),
        JobAuthorityProfile::Standard,
        runner_policy,
        pinned,
        plan_object,
        event_object,
        LogicalActivationBaseContextKind::Admission,
        base_context_object,
        Vec::new(),
        UnixMillis::new(10),
    )
    .expect("preparation descriptor");

    let inputs = child
        .inputs()
        .iter()
        .map(|input| {
            let (kind, digest) = match input.source() {
                ReusableInputBindingSource::Caller(value) => {
                    (AdmittedReusableInputKind::Caller, Some(json_digest(value)))
                }
                ReusableInputBindingSource::Default(value) => {
                    (AdmittedReusableInputKind::Default, Some(json_digest(value)))
                }
                ReusableInputBindingSource::ImplicitDefault => {
                    (AdmittedReusableInputKind::ImplicitDefault, None)
                }
            };
            ReusableWorkflowInputBindingEvidence::new(
                input.target(),
                input.input_type(),
                kind,
                digest,
            )
        })
        .collect();
    let secrets = child
        .secrets()
        .iter()
        .map(|edge| ReusableWorkflowSecretBindingEvidence::new(edge.target(), edge.source()))
        .collect();
    let permissions = ReusableWorkflowPermissionSnapshot::new(
        child.permissions().default_level(),
        child.permissions().grants().clone(),
        Sha256Digest::from_bytes([0x5d; 32]),
    );
    let call = ReadyReusableWorkflowCall::new(
        repository_id,
        preparation,
        child.id(),
        child_plan_object.clone(),
        inputs,
        secrets,
        permissions,
    );
    RuntimeFixture {
        call,
        child_plan,
        child_plan_object,
        secret,
    }
}

fn compile_root(source: &str) -> automata_ci_core::WorkflowPlan {
    let provenance = SourceProvenance::new(
        SourceId::new(ROOT_PATH),
        SourceOrigin::Repository {
            repository: Arc::from(REPOSITORY),
            revision: Arc::from(REVISION),
            path: Arc::from(ROOT_PATH),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let compiled = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed.plan().expect("root source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_commit_sha(REVISION)
            .with_git_ref(GIT_REF),
    ));
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    compiled.into_parts().0.expect("root plan")
}

async fn put_object(
    blobs: &MemoryBlobStore,
    key: &str,
    media_type: &str,
    bytes: Bytes,
) -> AdmissionObject {
    let payload = BlobPayload::from_bytes(
        BlobKey::new(key).expect("blob key"),
        MediaType::new(media_type).expect("media type"),
        bytes,
    );
    let descriptor = payload.descriptor().clone();
    blobs.put_if_absent(payload).await.expect("blob put");
    AdmissionObject::new(
        descriptor.digest(),
        ObjectKey::new(descriptor.key().as_str()).expect("object key"),
        descriptor.size(),
        descriptor.media_type().as_str(),
    )
    .expect("admission object")
}

async fn load_runtime_context(
    blobs: &MemoryBlobStore,
    object: &AdmissionObject,
) -> JobRuntimeContext {
    let descriptor = BlobDescriptor::new(
        BlobKey::new(object.object_key().as_str()).expect("blob key"),
        object.digest(),
        object.encoded_size(),
        MediaType::new(object.media_type()).expect("media type"),
    );
    let bytes = blobs
        .get_verified(&descriptor, object.encoded_size())
        .await
        .expect("runtime context")
        .into_bytes();
    automata_ci_protocol_protobuf::decode_job_runtime_context(&bytes, &ProtocolLimits::default())
        .expect("decoded runtime context")
}

fn json_digest(value: &impl serde::Serialize) -> Sha256Digest {
    Sha256Digest::from_bytes(
        Sha256::digest(serde_json::to_vec(value).expect("canonical JSON")).into(),
    )
}
