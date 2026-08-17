use crate::support;

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_blob::MemoryBlobStore;
use automata_ci_core::{
    ContextValue, JobRuntimeContext, QueuePolicy, SecretBinding, StrategyContext, UnixMillis,
    WorkflowEventProvenance,
};
use automata_ci_store::{
    AdmitLogicalWorkflowRun, AuthenticatedGithubDeliveryClaim, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId, ProviderDeliveryId,
    WorkflowAdmissionIdempotency, WorkflowAdmissionValueError,
};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubEventMetadata, GithubWorkflowCompiler, GithubWorkflowFrontend,
    ParseWorkflowRequest, SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use automata_ci_workflow_service::{
    GithubWorkflowPlanVerifier, WorkflowAdmissionError, WorkflowAdmissionFailure,
    WorkflowAdmissionObservation, WorkflowAdmissionObserver, WorkflowAdmissionRequest,
    WorkflowAdmissionRequestError, WorkflowAdmissionService, WorkflowAdmissionStage,
    WorkflowAdmissionStageOutcome,
};
use bytes::Bytes;
use uuid::Uuid;

#[tokio::test]
async fn run_name_is_evaluated_once_and_is_identical_on_replay() {
    let request = run_name_request(
        "run-name-replay",
        Some("Deploy ${{ inputs.target }} by @${{ github.actor }}"),
        Some("provider fallback"),
        Some("commit fallback"),
        "production",
    );
    let repository = Arc::new(ControllableRepository::default());
    let service = service(repository.clone());

    let first = service.admit(request.clone()).await.expect("new admission");
    let first_command = repository.take_command();
    assert!(!first.receipt().is_replay());
    assert_eq!(
        first_command.display_title(),
        Some("Deploy production by @synthetic-actor")
    );

    repository.mode.store(1, Ordering::SeqCst);
    let replay = service.admit(request).await.expect("exact replay");
    let replay_command = repository.take_command();
    assert!(replay.receipt().is_replay());
    assert_eq!(
        replay_command.display_title(),
        first_command.display_title()
    );
    assert_eq!(
        replay_command.request_digest(),
        first_command.request_digest()
    );
}

#[tokio::test]
async fn run_name_fallback_precedence_is_explicit_then_provider_then_commit() {
    let cases = [
        (
            "run-name-explicit",
            Some("explicit title"),
            Some("provider title"),
            Some("commit title"),
            Some("explicit title"),
        ),
        (
            "run-name-whitespace",
            Some("'   '"),
            Some("provider title"),
            Some("commit title"),
            Some("provider title"),
        ),
        (
            "run-name-commit",
            None,
            Some("   "),
            Some("commit title"),
            Some("commit title"),
        ),
        ("run-name-none", None, None, None, None),
    ];
    for (tenant, run_name, provider, commit, expected) in cases {
        let repository = Arc::new(ControllableRepository::default());
        service(repository.clone())
            .admit(run_name_request(
                tenant,
                run_name,
                provider,
                commit,
                "production",
            ))
            .await
            .expect("admission");
        assert_eq!(repository.take_command().display_title(), expected);
    }
}

#[tokio::test]
async fn run_name_has_exact_durable_byte_and_control_boundaries() {
    for (length, accepted) in [(1_023, true), (1_024, true), (1_025, false)] {
        let repository = Arc::new(ControllableRepository::default());
        let result = service(repository.clone())
            .admit(run_name_request(
                &format!("run-name-{length}"),
                Some(&"a".repeat(length)),
                None,
                None,
                "production",
            ))
            .await;
        if accepted {
            result.expect("bounded run-name");
            assert_eq!(
                repository
                    .take_command()
                    .display_title()
                    .expect("display title")
                    .len(),
                length
            );
        } else {
            assert!(matches!(
                result.expect_err("oversized run-name"),
                WorkflowAdmissionError::RunNameEvaluation
            ));
            assert!(repository.command.lock().expect("command lock").is_none());
        }
    }

    let repository = Arc::new(ControllableRepository::default());
    let error = service(repository.clone())
        .admit(run_name_request(
            "run-name-control",
            Some("\"bad\\nname\""),
            None,
            None,
            "production",
        ))
        .await
        .expect_err("control characters are not durable titles");
    assert!(matches!(error, WorkflowAdmissionError::RunNameEvaluation));
    assert!(repository.command.lock().expect("command lock").is_none());
}

#[tokio::test]
async fn human_projection_is_bound_into_the_logical_admission() {
    let original = support::ci_request(
        "logical-projection",
        WorkflowAdmissionIdempotency::provider_delivery(support::DELIVERY).expect("delivery"),
    );
    let request = WorkflowAdmissionRequest::builder(
        original.tenant().clone(),
        original.repository().clone(),
        original.workflow_path(),
        original.source().clone(),
        original.event().clone(),
        original.plan().clone(),
        original.base_context().clone(),
        original.idempotency().clone(),
        original.commit_sha(),
    )
    .git_ref(original.git_ref())
    .workflow_name(original.workflow_name())
    .actor("octocat")
    .display_title("Make projection durable")
    .commit_subject("Carry exact admission metadata")
    .run_attempt(7)
    .build()
    .expect("projected request");
    let repository = Arc::new(ControllableRepository::default());
    let service = service(repository.clone());

    service.admit(request).await.expect("admission");
    let command = repository.take_command();
    assert_eq!(command.workflow_name(), "CI");
    assert_eq!(command.git_ref(), support::GIT_REF);
    assert_eq!(command.actor(), Some("octocat"));
    assert_eq!(command.display_title(), Some("Make projection durable"));
    assert_eq!(
        command.commit_subject(),
        Some("Carry exact admission metadata")
    );
    assert_eq!(command.run_attempt(), 7);
    let concurrency = command.concurrency().expect("workflow concurrency");
    assert_eq!(concurrency.display_key(), "ci-CI-refs/heads/main");
    assert_eq!(concurrency.normalized_key(), "ci-ci-refs/heads/main");
    assert!(concurrency.cancel_in_progress());
    assert_eq!(concurrency.queue_policy(), QueuePolicy::Single);
    assert_eq!(repository.take_delivery_id(), None);
}

#[tokio::test]
async fn admission_resolves_max_queue_concurrency_from_safe_context() {
    let repository = Arc::new(ControllableRepository::default());
    service(repository.clone())
        .admit(concurrency_request(
            "logical-max-queue",
            "queue-${{ github.ref }}-${{ vars.channel }}",
            "github.ref != 'refs/heads/main'",
        ))
        .await
        .expect("max-queue admission");

    let command = repository.take_command();
    let concurrency = command.concurrency().expect("workflow concurrency");
    assert_eq!(concurrency.display_key(), "queue-refs/heads/main-stable");
    assert_eq!(concurrency.normalized_key(), "queue-refs/heads/main-stable");
    assert!(!concurrency.cancel_in_progress());
    assert_eq!(concurrency.queue_policy(), QueuePolicy::Max);
}

#[tokio::test]
async fn admission_rejects_expression_resolved_max_queue_conflict_before_store_commit() {
    let repository = Arc::new(ControllableRepository::default());
    let error = service(repository.clone())
        .admit(concurrency_request(
            "logical-max-queue-conflict",
            "queue-${{ github.ref }}",
            "github.ref == 'refs/heads/main'",
        ))
        .await
        .expect_err("resolved queue: max conflict must fail before persistence");

    assert!(matches!(
        error,
        WorkflowAdmissionError::AdmissionValue(
            WorkflowAdmissionValueError::InvalidConcurrencyPolicy
        )
    ));
    assert!(repository.command.lock().expect("command lock").is_none());
}

#[tokio::test]
async fn admission_rejects_late_bound_concurrency_before_store_commit() {
    let repository = Arc::new(ControllableRepository::default());
    let error = service(repository.clone())
        .admit(concurrency_request(
            "logical-late-concurrency",
            "queue-${{ github.run_number }}",
            "github.ref != 'refs/heads/main'",
        ))
        .await
        .expect_err("late-bound run identity must fail closed");

    assert!(matches!(
        error,
        WorkflowAdmissionError::ConcurrencyEvaluation
    ));
    assert!(repository.command.lock().expect("command lock").is_none());
}

#[tokio::test]
async fn authenticated_delivery_uses_the_distinct_store_path_and_digest() {
    let request = support::push_request("logical-provider-evidence");
    let local_repository = Arc::new(ControllableRepository::default());
    service(local_repository.clone())
        .admit(request.clone())
        .await
        .expect("ordinary admission");
    let local_digest = local_repository.take_command().request_digest();
    assert_eq!(local_repository.take_delivery_id(), None);

    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(42)).expect("delivery ID");
    let current_claim = authenticated_claim(delivery_id);
    let provider_repository = Arc::new(ControllableRepository::default());
    service(provider_repository.clone())
        .admit_authenticated_github_delivery(request, current_claim)
        .await
        .expect("authenticated delivery admission");
    let provider_digest = provider_repository.take_command().request_digest();
    assert_eq!(provider_repository.take_delivery_id(), Some(delivery_id));
    assert_ne!(provider_digest, local_digest);
}

#[tokio::test]
async fn base_context_metadata_and_request_digest_bind_every_admitted_value() {
    let original = support::operation_request("logical-base-context");
    let first_base = JobRuntimeContext::new_base(
        context_object([("target", ContextValue::string("base-input-sentinel"))]),
        context_object([("channel", ContextValue::string("base-var-sentinel"))]),
        BTreeMap::from([(
            "DEPLOY_TOKEN".to_owned(),
            SecretBinding::new("base-binding-sentinel")
                .expect("binding")
                .with_version_id("base-version-sentinel")
                .expect("version"),
        )]),
    )
    .expect("base context");
    let second_base = JobRuntimeContext::new_base(
        context_object([("target", ContextValue::string("changed-input"))]),
        context_object([("channel", ContextValue::string("base-var-sentinel"))]),
        BTreeMap::from([(
            "DEPLOY_TOKEN".to_owned(),
            SecretBinding::new("base-binding-sentinel")
                .expect("binding")
                .with_version_id("base-version-sentinel")
                .expect("version"),
        )]),
    )
    .expect("changed base context");
    let first_request = rebuild_with_base(&original, first_base);
    let second_request = rebuild_with_base(&original, second_base);
    let debug = format!("{first_request:?}");
    for redacted in [
        "base-input-sentinel",
        "base-var-sentinel",
        "base-binding-sentinel",
        "base-version-sentinel",
    ] {
        assert!(
            !debug.contains(redacted),
            "request Debug exposed {redacted}"
        );
    }

    let first_repository = Arc::new(ControllableRepository::default());
    service(first_repository.clone())
        .admit(first_request)
        .await
        .expect("first admission");
    let first = first_repository.take_command();
    let second_repository = Arc::new(ControllableRepository::default());
    service(second_repository.clone())
        .admit(second_request)
        .await
        .expect("second admission");
    let second = second_repository.take_command();

    let first_context = first.base_context().expect("first base descriptor");
    let second_context = second.base_context().expect("second base descriptor");
    assert_eq!(
        first_context.media_type(),
        automata_ci_workflow_service::JOB_RUNTIME_CONTEXT_MEDIA_TYPE
    );
    assert_ne!(first_context.digest(), second_context.digest());
    assert_ne!(first.request_digest(), second.request_digest());
}

#[test]
fn admission_rejects_instance_context_as_a_base_context() {
    let original = support::operation_request("logical-invalid-base-context");
    let instance_context = JobRuntimeContext::new(
        ContextValue::empty_object(),
        ContextValue::empty_object(),
        context_object([("target", ContextValue::string("linux"))]),
        StrategyContext::new(true, 0, 1, 1).expect("strategy"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("instance context");

    assert!(matches!(
        try_rebuild_with_base(&original, instance_context),
        Err(WorkflowAdmissionRequestError::InvalidBaseContext)
    ));
}

#[tokio::test]
async fn provider_only_entrypoint_rejects_operation_admission_before_the_store() {
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(43)).expect("delivery ID");
    let current_claim = authenticated_claim(delivery_id);
    let repository = Arc::new(ControllableRepository::default());
    assert!(matches!(
        service(repository.clone())
            .admit_authenticated_github_delivery(
                support::operation_request("logical-local-absence"),
                current_claim,
            )
            .await
            .expect_err("operation admission cannot claim provider evidence"),
        WorkflowAdmissionError::Internal
    ));
    assert!(repository.command.lock().expect("command lock").is_none());
    assert!(
        repository
            .delivery_ids
            .lock()
            .expect("delivery capture lock")
            .is_empty()
    );
}

#[tokio::test]
async fn observer_distinguishes_new_replay_and_durable_failure() {
    let request = support::operation_request("logical-observer");
    let job_count = request.plan().jobs().len();
    let repository = Arc::new(ControllableRepository::default());
    let observer = Arc::new(RecordingObserver::default());
    let service = service(repository.clone()).with_observer(observer.clone());

    service.admit(request.clone()).await.expect("new admission");
    repository.mode.store(1, Ordering::SeqCst);
    service
        .admit(request.clone())
        .await
        .expect("receipt replay");
    repository.mode.store(2, Ordering::SeqCst);
    assert!(matches!(
        service.admit(request).await.expect_err("durable conflict"),
        WorkflowAdmissionError::Store(LogicalWorkflowAdmissionStoreError::IdempotencyConflict)
    ));

    assert_eq!(
        *observer.admissions.lock().expect("admission lock"),
        [
            WorkflowAdmissionObservation::New { jobs: job_count },
            WorkflowAdmissionObservation::Replay,
            WorkflowAdmissionObservation::Failed(WorkflowAdmissionFailure::DurableStore),
        ]
    );
    let stages = observer.stages.lock().expect("stage lock");
    assert_eq!(stages.len(), 15);
    for attempt in stages.chunks_exact(5).take(2) {
        assert_eq!(
            attempt,
            [
                (
                    WorkflowAdmissionStage::Prepare,
                    WorkflowAdmissionStageOutcome::Success
                ),
                (
                    WorkflowAdmissionStage::Materialize,
                    WorkflowAdmissionStageOutcome::Success
                ),
                (
                    WorkflowAdmissionStage::Encode,
                    WorkflowAdmissionStageOutcome::Success
                ),
                (
                    WorkflowAdmissionStage::Publish,
                    WorkflowAdmissionStageOutcome::Success
                ),
                (
                    WorkflowAdmissionStage::Commit,
                    WorkflowAdmissionStageOutcome::Success
                ),
            ]
        );
    }
    assert_eq!(
        &stages[10..],
        [
            (
                WorkflowAdmissionStage::Prepare,
                WorkflowAdmissionStageOutcome::Success
            ),
            (
                WorkflowAdmissionStage::Materialize,
                WorkflowAdmissionStageOutcome::Success
            ),
            (
                WorkflowAdmissionStage::Encode,
                WorkflowAdmissionStageOutcome::Success
            ),
            (
                WorkflowAdmissionStage::Publish,
                WorkflowAdmissionStageOutcome::Success
            ),
            (
                WorkflowAdmissionStage::Commit,
                WorkflowAdmissionStageOutcome::Failure
            ),
        ]
    );
}

fn service(repository: Arc<ControllableRepository>) -> WorkflowAdmissionService {
    WorkflowAdmissionService::with_system_ports(
        Arc::new(MemoryBlobStore::default()),
        repository,
        Arc::new(GithubWorkflowPlanVerifier::new()),
    )
}

fn concurrency_request(
    tenant: &str,
    group: &str,
    cancel_condition: &str,
) -> WorkflowAdmissionRequest {
    let source = format!(
        r"name: Queue contract
on: push
concurrency:
  group: {group}
  cancel-in-progress: ${{{{ {cancel_condition} }}}}
  queue: max
jobs:
  verify:
    runs-on: linux
    steps:
      - run: echo synthetic
"
    );
    let provenance = SourceProvenance::new(
        SourceId::new(".ci/workflows/queue.yml"),
        SourceOrigin::Repository {
            repository: Arc::from(support::REPOSITORY),
            revision: automata_ci_core::GitObjectId::from_provider_hex(support::REVISION)
                .expect("revision"),
            path: Arc::from(".ci/workflows/queue.yml"),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, &source));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let compiled = GithubWorkflowCompiler::new().compile(
        CompileWorkflowRequest::new(
            parsed.plan().expect("parsed plan"),
            WorkflowEventProvenance::new("github", "push")
                .with_delivery_id(support::DELIVERY)
                .with_commit_sha(
                    automata_ci_core::GitObjectId::from_provider_hex(support::REVISION)
                        .expect("revision"),
                )
                .with_git_ref(support::GIT_REF),
        )
        .with_event_metadata(GithubEventMetadata::push(false)),
    );
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    let base_context = JobRuntimeContext::new_base(
        ContextValue::empty_object(),
        context_object([("channel", ContextValue::string("stable"))]),
        BTreeMap::new(),
    )
    .expect("base context");
    WorkflowAdmissionRequest::builder(
        automata_ci_store::TenantScope::from_authenticated_tenant_id(tenant).expect("tenant"),
        automata_ci_workflow_service::AdmissionRepositoryCoordinates::new(
            "github",
            "repository-queue",
            "automata-ci",
            "automata",
        )
        .expect("repository"),
        ".ci/workflows/queue.yml",
        Bytes::from(source),
        Bytes::from_static(b"{\"deleted\":false}"),
        compiled.into_parts().0.expect("compiled plan"),
        base_context,
        WorkflowAdmissionIdempotency::operation(automata_ci_core::OperationId::new()),
        automata_ci_core::GitObjectId::from_provider_hex(support::REVISION).expect("revision"),
    )
    .git_ref(support::GIT_REF)
    .workflow_name("Queue contract")
    .actor("synthetic-actor")
    .run_attempt(1)
    .build()
    .expect("admission request")
}

fn run_name_request(
    tenant: &str,
    run_name: Option<&str>,
    display_title: Option<&str>,
    commit_subject: Option<&str>,
    target: &str,
) -> WorkflowAdmissionRequest {
    let run_name = run_name.map_or_else(String::new, |value| format!("run-name: {value}\n"));
    let source = format!(
        "{run_name}name: Run-name contract\non: push\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo synthetic\n"
    );
    let provenance = SourceProvenance::new(
        SourceId::new(".ci/workflows/run-name.yml"),
        SourceOrigin::Repository {
            repository: Arc::from(support::REPOSITORY),
            revision: automata_ci_core::GitObjectId::from_provider_hex(support::REVISION)
                .expect("revision"),
            path: Arc::from(".ci/workflows/run-name.yml"),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, &source));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let compiled = GithubWorkflowCompiler::new().compile(
        CompileWorkflowRequest::new(
            parsed.plan().expect("parsed plan"),
            WorkflowEventProvenance::new("github", "push")
                .with_delivery_id(support::DELIVERY)
                .with_commit_sha(
                    automata_ci_core::GitObjectId::from_provider_hex(support::REVISION)
                        .expect("revision"),
                )
                .with_git_ref(support::GIT_REF),
        )
        .with_event_metadata(GithubEventMetadata::push(false)),
    );
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    let base_context = JobRuntimeContext::new_base(
        context_object([("target", ContextValue::string(target))]),
        ContextValue::empty_object(),
        BTreeMap::new(),
    )
    .expect("base context");
    let mut builder = WorkflowAdmissionRequest::builder(
        automata_ci_store::TenantScope::from_authenticated_tenant_id(tenant).expect("tenant"),
        automata_ci_workflow_service::AdmissionRepositoryCoordinates::new(
            "github",
            "repository-run-name",
            "automata-ci",
            "automata",
        )
        .expect("repository"),
        ".ci/workflows/run-name.yml",
        Bytes::from(source),
        Bytes::from_static(b"{\"deleted\":false}"),
        compiled.into_parts().0.expect("compiled plan"),
        base_context,
        WorkflowAdmissionIdempotency::operation(automata_ci_core::OperationId::new()),
        automata_ci_core::GitObjectId::from_provider_hex(support::REVISION).expect("revision"),
    )
    .git_ref(support::GIT_REF)
    .workflow_name("Run-name contract")
    .actor("synthetic-actor")
    .run_attempt(1);
    if let Some(display_title) = display_title {
        builder = builder.display_title(display_title);
    }
    if let Some(commit_subject) = commit_subject {
        builder = builder.commit_subject(commit_subject);
    }
    builder.build().expect("admission request")
}

fn context_object(entries: impl IntoIterator<Item = (&'static str, ContextValue)>) -> ContextValue {
    ContextValue::object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .expect("context object")
}

fn rebuild_with_base(
    original: &WorkflowAdmissionRequest,
    base_context: JobRuntimeContext,
) -> WorkflowAdmissionRequest {
    try_rebuild_with_base(original, base_context).expect("rebuilt request")
}

fn try_rebuild_with_base(
    original: &WorkflowAdmissionRequest,
    base_context: JobRuntimeContext,
) -> Result<WorkflowAdmissionRequest, WorkflowAdmissionRequestError> {
    WorkflowAdmissionRequest::builder(
        original.tenant().clone(),
        original.repository().clone(),
        original.workflow_path(),
        original.source().clone(),
        original.event().clone(),
        original.plan().clone(),
        base_context,
        original.idempotency().clone(),
        original.commit_sha(),
    )
    .git_ref(original.git_ref())
    .workflow_name(original.workflow_name())
    .actor(original.actor().expect("fixture actor"))
    .run_attempt(original.run_attempt().expect("fixture attempt"))
    .build()
}

#[derive(Debug, Default)]
struct ControllableRepository {
    command: Mutex<Option<AdmitLogicalWorkflowRun>>,
    delivery_ids: Mutex<Vec<Option<ProviderDeliveryId>>>,
    mode: AtomicU8,
}

impl ControllableRepository {
    fn take_command(&self) -> AdmitLogicalWorkflowRun {
        self.command
            .lock()
            .expect("capture lock")
            .take()
            .expect("captured command")
    }

    fn take_delivery_id(&self) -> Option<ProviderDeliveryId> {
        self.delivery_ids
            .lock()
            .expect("delivery capture lock")
            .pop()
            .expect("captured admission path")
    }

    fn record(
        &self,
        command: AdmitLogicalWorkflowRun,
        delivery_id: Option<ProviderDeliveryId>,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        if self.mode.load(Ordering::SeqCst) == 2 {
            return Err(LogicalWorkflowAdmissionStoreError::IdempotencyConflict);
        }
        let receipt = LogicalWorkflowAdmissionReceipt::new(
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            command.root_invocation_id(),
            1,
            self.mode.load(Ordering::SeqCst) == 1,
        );
        *self.command.lock().expect("capture lock") = Some(command);
        self.delivery_ids
            .lock()
            .expect("delivery capture lock")
            .push(delivery_id);
        Ok(receipt)
    }
}

impl LogicalWorkflowAdmissionRepository for ControllableRepository {
    fn admit_logical_workflow<'life0, 'async_trait>(
        &'life0 self,
        command: AdmitLogicalWorkflowRun,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        LogicalWorkflowAdmissionReceipt,
                        LogicalWorkflowAdmissionStoreError,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.record(command, None) })
    }

    fn admit_authenticated_github_delivery<'life0, 'async_trait>(
        &'life0 self,
        command: AdmitLogicalWorkflowRun,
        current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        LogicalWorkflowAdmissionReceipt,
                        LogicalWorkflowAdmissionStoreError,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            assert_eq!(command.admitted_at(), observed_at);
            self.record(command, Some(current_claim.claim().delivery_id()))
        })
    }
}

fn authenticated_claim(delivery_id: ProviderDeliveryId) -> AuthenticatedGithubDeliveryClaim {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_millis(),
    )
    .expect("current time fits i64");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(900)).expect("claim owner");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 1).expect("claim fence");
    AuthenticatedGithubDeliveryClaim::new(
        claim,
        1,
        UnixMillis::new(now - 60_000),
        UnixMillis::new(now + 60_000),
    )
    .expect("authenticated claim")
}

#[derive(Debug, Default)]
struct RecordingObserver {
    stages: Mutex<Vec<(WorkflowAdmissionStage, WorkflowAdmissionStageOutcome)>>,
    admissions: Mutex<Vec<WorkflowAdmissionObservation>>,
}

impl WorkflowAdmissionObserver for RecordingObserver {
    fn observe_stage(
        &self,
        stage: WorkflowAdmissionStage,
        outcome: WorkflowAdmissionStageOutcome,
        _duration: Duration,
    ) {
        self.stages
            .lock()
            .expect("stage lock")
            .push((stage, outcome));
    }

    fn observe_admission(&self, outcome: WorkflowAdmissionObservation, _duration: Duration) {
        self.admissions
            .lock()
            .expect("admission lock")
            .push(outcome);
    }
}
