use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_blob::MemoryBlobStore;
use automata_ci_core::{GitObjectId, Sha256Digest, TrustTokenRecursion, UnixMillis, WorkspaceId};
use automata_ci_provider::{
    ClaimProviderResult, ClaimedProviderProcessing, ClaimedProviderResult, CompleteProviderResult,
    ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId, ExternalRepositoryIdentity,
    ExternalSubjectId, FailProviderResult, NormalizedTrigger, ProviderArchiveLimits,
    ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderConnectionRevision,
    ProviderDefaultBranch, ProviderDeliveryEvidence, ProviderDeliveryId,
    ProviderDeliveryObservations, ProviderEventName, ProviderGitRef, ProviderGitRefKind,
    ProviderInstanceId, ProviderLifecycleState, ProviderProcessingClaimFence,
    ProviderProcessingClaimSource, ProviderProcessingInput, ProviderProcessingInvocationId,
    ProviderProcessingReceipt, ProviderProcessingState, ProviderProcessingWorkerId,
    ProviderRepository, ProviderRepositoryPath, ProviderResultClaimFence, ProviderResultFuture,
    ProviderResultRepository, ProviderResultRepositoryError, ProviderResultSaveOutcome,
    ProviderResultSubject, ProviderRunnerPolicyBinding, ProviderSchemaVersion,
    ProviderSecretGeneration, ProviderSecretName, ProviderTypeId, ProviderWebhookEndpointId,
    ProviderWebhookEndpointRevision, ProviderWebhookSecretReference,
    ProviderWebhookSignatureEvidence, ProviderWorkflowSource, PushCommitEvidence, PushTrigger,
    RenewProviderResult, RepositoryVisibility, RetryProviderResult, SaveDesiredProviderResult,
    VerifiedProviderTriggerDelivery, provider_raw_webhook_descriptor,
};
use automata_ci_provider_delivery::{ProviderTrustContext, derive_provider_trust_snapshot};
use automata_ci_scm::{
    ArchiveFormat, RepositoryId, RepositorySourceArchive, RepositorySourceConnection,
};
use automata_ci_store::{
    AdmitLogicalWorkflowRun, AuthenticatedProviderDeliveryClaim, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError,
    WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_actions::{ProviderChangedFiles, ProviderEventMetadata};
use automata_ci_workflow_service::{
    GithubWorkflowPlanVerifier, ProviderWorkflowApplicationOutcome,
    ProviderWorkflowApplicationRequest, ProviderWorkflowApplicationService,
    ProviderWorkflowDisposition, ProviderWorkflowRejection, ProviderWorkflowResultService,
    WorkflowAdmissionService,
};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, EntryType, Header};
use url::Url;
use uuid::Uuid;

const WORKFLOW_PATH: &str = ".ci/workflows/ci.yml";
const BEFORE: &str = "0000000000000000000000000000000000000001";
const AFTER: &str = "1111111111111111111111111111111111111111";

const PUSH_WORKFLOW: &[u8] = br"name: CI
on:
  push:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: echo verified
";

const MANUAL_WORKFLOW: &[u8] = br"name: Manual
on:
  workflow_dispatch:
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: echo manual
";

const FILTERED_WORKFLOW: &[u8] = br"name: Filtered
on:
  push:
    paths:
      - src/**
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: echo filtered
";

#[derive(Debug, Default)]
struct Admissions {
    commands: Mutex<Vec<AdmitLogicalWorkflowRun>>,
}

#[async_trait]
impl LogicalWorkflowAdmissionRepository for Admissions {
    async fn admit_logical_workflow(
        &self,
        _command: AdmitLogicalWorkflowRun,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
    }

    async fn admit_authenticated_provider_delivery(
        &self,
        command: AdmitLogicalWorkflowRun,
        current_claim: AuthenticatedProviderDeliveryClaim,
        observed_at: UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        assert_eq!(command.admitted_at(), observed_at);
        assert_eq!(current_claim.delivery_id(), fixture_delivery_id());
        assert_eq!(
            command.idempotency(),
            &WorkflowAdmissionIdempotency::namespaced_provider_delivery(
                "github",
                "42",
                "delivery-1",
                WORKFLOW_PATH,
            )
            .expect("expected admission identity")
        );
        let receipt = LogicalWorkflowAdmissionReceipt::new(
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            command.root_invocation_id(),
            1,
            false,
        );
        self.commands.lock().expect("command lock").push(command);
        Ok(receipt)
    }
}

#[derive(Debug, Default)]
struct Results {
    desired: Mutex<Vec<SaveDesiredProviderResult>>,
}

impl ProviderResultRepository for Results {
    fn load_workflow_subject(
        &self,
        _run_id: automata_ci_core::RunId,
    ) -> ProviderResultFuture<'_, Option<ProviderResultSubject>> {
        Box::pin(async { Ok(None) })
    }

    fn save_desired(
        &self,
        request: SaveDesiredProviderResult,
    ) -> ProviderResultFuture<'_, ProviderResultSaveOutcome> {
        Box::pin(async move {
            self.desired.lock().expect("result lock").push(request);
            Ok(ProviderResultSaveOutcome::Inserted)
        })
    }

    fn claim_result(
        &self,
        _request: ClaimProviderResult,
    ) -> ProviderResultFuture<'_, Option<ClaimedProviderResult>> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }

    fn complete_result(&self, _request: CompleteProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }

    fn renew_result(
        &self,
        _request: RenewProviderResult,
    ) -> ProviderResultFuture<'_, ProviderResultClaimFence> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }

    fn retry_result(&self, _request: RetryProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }

    fn fail_result(&self, _request: FailProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }
}

#[derive(Debug)]
struct CurrentClaim(ProviderProcessingClaimFence);

impl ProviderProcessingClaimSource for CurrentClaim {
    fn current_fence(&self) -> ProviderProcessingClaimFence {
        self.0
    }
}

struct Harness {
    service: ProviderWorkflowApplicationService,
    connection: ProviderConnectionManifest,
    delivery: VerifiedProviderTriggerDelivery,
    processing: ClaimedProviderProcessing,
    claim_source: Arc<dyn ProviderProcessingClaimSource>,
    admissions: Arc<Admissions>,
    results: Arc<Results>,
}

impl Harness {
    fn request(&self, workflow: &[u8]) -> ProviderWorkflowApplicationRequest {
        self.request_with_metadata(
            workflow,
            ProviderEventMetadata::from_normalized_trigger(self.delivery.trigger().trigger()),
        )
    }

    fn request_with_metadata(
        &self,
        workflow: &[u8],
        metadata: ProviderEventMetadata,
    ) -> ProviderWorkflowApplicationRequest {
        let source = RepositorySourceArchive::from_bytes(
            RepositorySourceConnection::new(
                self.connection.connection_id(),
                self.connection
                    .configuration()
                    .repository()
                    .external_id()
                    .clone(),
                RepositoryId::new("owner/repository").expect("repository route"),
            ),
            object(AFTER),
            ArchiveFormat::TarGzip,
            archive(BTreeMap::from([(WORKFLOW_PATH, workflow)])),
        );
        let normalized = self.delivery.trigger().trigger();
        let execution_ref = normalized
            .workflow_execution_ref()
            .expect("push execution ref")
            .clone();
        let trust = derive_provider_trust_snapshot(
            normalized,
            &ProviderTrustContext::new(
                object(AFTER),
                execution_ref.clone(),
                object(AFTER),
                TrustTokenRecursion::Suppressed,
            ),
        )
        .expect("trust snapshot");
        ProviderWorkflowApplicationRequest::new(
            self.connection.clone(),
            self.delivery.clone(),
            self.processing.clone(),
            Arc::clone(&self.claim_source),
            source,
            execution_ref,
            trust,
            metadata,
        )
        .expect("application request")
    }
}

#[tokio::test]
async fn accepted_workflow_uses_common_admission_and_projects_queued_result() {
    let harness = harness();
    let outcome = harness
        .service
        .apply(harness.request(PUSH_WORKFLOW))
        .await
        .expect("application");
    let ProviderWorkflowApplicationOutcome::Applied(reports) = outcome else {
        panic!("push workflow must be applied");
    };
    assert_eq!(reports.len(), 1);
    assert!(matches!(
        reports[0].disposition(),
        ProviderWorkflowDisposition::Admitted(_)
    ));
    assert_eq!(
        harness
            .admissions
            .commands
            .lock()
            .expect("command lock")
            .len(),
        1
    );
    let desired = harness.results.desired.lock().expect("result lock");
    assert_eq!(desired.len(), 1);
    assert_eq!(
        desired[0].projection().phase(),
        automata_ci_provider::ProviderResultPhase::Queued
    );
    assert_eq!(desired[0].projection().conclusion(), None);
}

#[tokio::test]
async fn non_selected_and_invalid_workflows_project_terminal_common_results() {
    let not_selected = harness();
    let outcome = not_selected
        .service
        .apply(not_selected.request(MANUAL_WORKFLOW))
        .await
        .expect("not-selected application");
    let ProviderWorkflowApplicationOutcome::Applied(reports) = outcome else {
        panic!("manual workflow must resolve deterministically");
    };
    assert!(matches!(
        reports[0].disposition(),
        ProviderWorkflowDisposition::NotSelected(_)
    ));
    {
        let desired = not_selected.results.desired.lock().expect("result lock");
        assert_eq!(desired.len(), 1);
        assert_eq!(
            desired[0].projection().conclusion(),
            Some(automata_ci_provider::ProviderResultConclusion::Skipped)
        );
    }

    let invalid = harness();
    let outcome = invalid
        .service
        .apply(invalid.request(b"not: [valid"))
        .await
        .expect("invalid application");
    let ProviderWorkflowApplicationOutcome::Applied(reports) = outcome else {
        panic!("invalid workflow must resolve deterministically");
    };
    assert_eq!(
        reports[0].disposition(),
        &ProviderWorkflowDisposition::Rejected(ProviderWorkflowRejection::Frontend)
    );
    let desired = invalid.results.desired.lock().expect("result lock");
    assert_eq!(desired.len(), 1);
    assert_eq!(
        desired[0].projection().conclusion(),
        Some(automata_ci_provider::ProviderResultConclusion::Failure)
    );
    assert!(
        invalid
            .admissions
            .commands
            .lock()
            .expect("command lock")
            .is_empty()
    );
}

#[tokio::test]
async fn path_filtered_workflow_waits_for_provider_evidence_before_admission() {
    let harness = harness();
    let initial = harness
        .service
        .apply(harness.request(FILTERED_WORKFLOW))
        .await
        .expect("initial application");
    assert_eq!(
        initial,
        ProviderWorkflowApplicationOutcome::RequiresChangedFiles
    );
    assert!(
        harness
            .admissions
            .commands
            .lock()
            .expect("command lock")
            .is_empty()
    );
    assert!(
        harness
            .results
            .desired
            .lock()
            .expect("result lock")
            .is_empty()
    );

    let metadata =
        ProviderEventMetadata::from_normalized_trigger(harness.delivery.trigger().trigger())
            .with_changed_files(ProviderChangedFiles::complete_selection_with_evidence(
                ["src/lib.rs"],
                1,
                Sha256Digest::from_bytes([0x44; 32]),
            ))
            .expect("push changed-file metadata");
    let resolved = harness
        .service
        .apply(harness.request_with_metadata(FILTERED_WORKFLOW, metadata))
        .await
        .expect("resolved application");
    let ProviderWorkflowApplicationOutcome::Applied(reports) = resolved else {
        panic!("verified changed files must resolve selection");
    };
    assert!(matches!(
        reports[0].disposition(),
        ProviderWorkflowDisposition::Admitted(_)
    ));
    assert_eq!(
        harness
            .admissions
            .commands
            .lock()
            .expect("command lock")
            .len(),
        1
    );
    assert_eq!(
        harness.results.desired.lock().expect("result lock").len(),
        1
    );
}

fn harness() -> Harness {
    let (connection, delivery, processing, fence) = evidence();
    let blobs = Arc::new(MemoryBlobStore::default());
    let admissions = Arc::new(Admissions::default());
    let admission = WorkflowAdmissionService::with_system_ports(
        blobs,
        admissions.clone(),
        Arc::new(GithubWorkflowPlanVerifier::new()),
    );
    let results = Arc::new(Results::default());
    let result_service = ProviderWorkflowResultService::new(
        results.clone(),
        Url::parse("https://ci.automata.example/").expect("dashboard origin"),
    )
    .expect("result service");
    Harness {
        service: ProviderWorkflowApplicationService::new(admission, result_service),
        connection,
        delivery,
        processing,
        claim_source: Arc::new(CurrentClaim(fence)),
        admissions,
        results,
    }
}

fn evidence() -> (
    ProviderConnectionManifest,
    VerifiedProviderTriggerDelivery,
    ClaimedProviderProcessing,
    ProviderProcessingClaimFence,
) {
    let instance_id = ProviderInstanceId::from_uuid(Uuid::from_u128(1)).expect("instance");
    let provider_revision = ProviderConfigurationRevision::new(1).expect("provider revision");
    let connection_id = ProviderConnectionId::from_uuid(Uuid::from_u128(2)).expect("connection");
    let connection_revision = ProviderConnectionRevision::new(1).expect("connection revision");
    let repository_identity = ExternalRepositoryIdentity::new(
        instance_id,
        ExternalRepositoryId::new("42").expect("repository ID"),
    );
    let delivery = trigger_delivery(
        instance_id,
        provider_revision,
        connection_id,
        connection_revision,
        &repository_identity,
    );
    let (processing, fence) = claimed_processing(&delivery);
    let connection = connection_manifest(
        connection_id,
        connection_revision,
        provider_revision,
        repository_identity,
    );
    (connection, delivery, processing, fence)
}

fn trigger_delivery(
    instance_id: ProviderInstanceId,
    provider_revision: ProviderConfigurationRevision,
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    repository_identity: &ExternalRepositoryIdentity,
) -> VerifiedProviderTriggerDelivery {
    let repository = ProviderRepository::new(
        repository_identity.clone(),
        ExternalSubjectId::new("7").expect("owner ID"),
        ProviderRepositoryPath::new("owner/repository").expect("repository path"),
        RepositoryVisibility::Private,
    );
    let git_ref =
        ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("branch ref");
    let push = PushTrigger::new(
        repository,
        git_ref,
        Some(object(BEFORE)),
        Some(object(AFTER)),
        PushCommitEvidence::complete([object(AFTER)]).expect("commit evidence"),
        false,
        None,
    )
    .expect("push trigger");
    let sealed = NormalizedTrigger::Push(push)
        .seal()
        .expect("sealed trigger");
    let raw = provider_raw_webhook_descriptor(Sha256Digest::from_bytes([7; 32]), 1)
        .expect("raw descriptor");
    let delivery_id = fixture_delivery_id();
    let delivery_evidence = ProviderDeliveryEvidence::rehydrate(
        delivery_id,
        ProviderWebhookEndpointId::from_uuid(Uuid::from_u128(3)).expect("endpoint"),
        ProviderWebhookEndpointRevision::new(1).expect("endpoint revision"),
        ProviderTypeId::new("github").expect("provider type"),
        instance_id,
        provider_revision,
        connection_id,
        connection_revision,
        ExternalDeliveryIdentity::new(
            instance_id,
            ExternalDeliveryId::new("delivery-1").expect("delivery identity"),
        ),
        ProviderEventName::new("push").expect("event name"),
        UnixMillis::new(900),
        raw,
        UnixMillis::new(10_000),
        ProviderWebhookSignatureEvidence::new(
            "github-hmac-sha256",
            ProviderWebhookSecretReference::new(
                provider_revision,
                ProviderSecretName::new("webhook-secret").expect("secret name"),
                ProviderSecretGeneration::new(1).expect("secret generation"),
            ),
        )
        .expect("signature evidence"),
        ProviderDeliveryObservations::new(Vec::new()).expect("observations"),
    )
    .expect("delivery evidence");
    VerifiedProviderTriggerDelivery::rehydrate(delivery_evidence, sealed)
        .expect("verified delivery")
}

fn claimed_processing(
    delivery: &VerifiedProviderTriggerDelivery,
) -> (ClaimedProviderProcessing, ProviderProcessingClaimFence) {
    let delivery_id = delivery.evidence().delivery_id();
    let receipt = ProviderProcessingReceipt::new(
        ProviderProcessingInvocationId::from_uuid(Uuid::from_u128(4)).expect("invocation"),
        delivery_id,
        Some(delivery_id),
        ProviderProcessingState::Claimed,
        1,
        UnixMillis::new(1_000),
    )
    .expect("processing receipt");
    let fence = ProviderProcessingClaimFence::new(
        receipt.invocation_id(),
        ProviderProcessingWorkerId::from_uuid(Uuid::from_u128(5)).expect("worker"),
        1,
        UnixMillis::new(1_100),
        UnixMillis::new(301_100),
    )
    .expect("processing fence");
    let processing = ClaimedProviderProcessing::new(
        receipt,
        ProviderProcessingInput::Trigger(Box::new(delivery.clone())),
        fence,
    )
    .expect("claimed processing");
    (processing, fence)
}

fn connection_manifest(
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    provider_revision: ProviderConfigurationRevision,
    repository_identity: ExternalRepositoryIdentity,
) -> ProviderConnectionManifest {
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        repository_identity,
        provider_revision,
        Sha256Digest::from_bytes([8; 32]),
        Sha256Digest::from_bytes([9; 32]),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("default branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".ci/workflows").expect("workflow root"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner schema"),
            Sha256Digest::from_bytes([10; 32]),
        ),
        ProviderArchiveLimits::new(
            1_024 * 1_024,
            8 * 1_024 * 1_024,
            1_000,
            1_024,
            100,
            1_024 * 1_024,
        )
        .expect("archive limits"),
        ProviderConnectionPolicyDocument::new(
            ProviderSchemaVersion::new(1).expect("policy schema"),
            b"{}".to_vec(),
        )
        .expect("connection policy"),
    );
    ProviderConnectionManifest::new(
        connection_id,
        connection_revision,
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(100),
        Some(UnixMillis::new(100)),
        None,
    )
    .expect("connection manifest")
}

fn fixture_delivery_id() -> ProviderDeliveryId {
    ProviderDeliveryId::from_uuid(Uuid::from_u128(6)).expect("delivery")
}

fn object(value: &str) -> GitObjectId {
    GitObjectId::from_provider_hex(value).expect("object ID")
}

fn archive<T: AsRef<[u8]>>(files: BTreeMap<&str, T>) -> Bytes {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    append_entry(&mut builder, "repository-root", EntryType::Directory, &[]);
    for (path, bytes) in files {
        append_entry(
            &mut builder,
            &format!("repository-root/{path}"),
            EntryType::Regular,
            bytes.as_ref(),
        );
    }
    let encoder = builder.into_inner().expect("finish tar");
    Bytes::from(encoder.finish().expect("finish gzip"))
}

fn append_entry(
    builder: &mut Builder<GzEncoder<Vec<u8>>>,
    path: &str,
    kind: EntryType,
    bytes: &[u8],
) {
    let mut header = Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(if kind.is_dir() { 0o755 } else { 0o644 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(u64::try_from(bytes.len()).expect("entry size"));
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .expect("append archive entry");
}
