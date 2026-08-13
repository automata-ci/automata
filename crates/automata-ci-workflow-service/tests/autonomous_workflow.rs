use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_core::{
    JobAuthorityProfile, RunId, RunIdAlias, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    AdmissionObject, BindLogicalActivationPreparation, ClaimNextLogicalInstanceMaterialization,
    ClaimNextLogicalJobOrchestration, ClaimedLogicalActivationPreparation,
    ClaimedLogicalInstanceMaterialization, ClaimedLogicalJobActivation,
    CommitLogicalInstanceMaterialization, ConsumeSelectedLogicalInstanceMaterialization,
    ConsumeSelectedLogicalJobOrchestration, ConsumedLogicalJobOrchestrationAuthority,
    ConsumedSelectedLogicalInstanceMaterialization, ConsumedSelectedLogicalJobOrchestration,
    GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE,
    LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE, LogicalActivationBaseContextKind,
    LogicalActivationClaimFence, LogicalActivationExecutionContext, LogicalActivationGeneration,
    LogicalActivationObject, LogicalActivationPreparationClaimFence,
    LogicalActivationPreparationDescriptor, LogicalActivationPreparationGeneration,
    LogicalActivationPreparationStore, LogicalActivationPreparationStoreError,
    LogicalActivationPreparationTarget, LogicalActivationRepository, LogicalActivationStoreError,
    LogicalActivationWorkerId, LogicalInstanceMaterializationDescriptor,
    LogicalInstanceMaterializationSelectionOutcome, LogicalInstanceMaterializationTarget,
    LogicalJobOrchestrationAuthorityKind, LogicalJobOrchestrationSelectionOutcome,
    LogicalMaterializationClaimFence, LogicalMaterializationGeneration,
    LogicalMaterializationRepository, LogicalMaterializationStoreError,
    LogicalMaterializationWorkerId, LogicalWorkQuarantineKind, LogicalWorkQuarantineOutcome,
    LogicalWorkSelectionGeneration, LogicalWorkSelectionId, LogicalWorkSelectionRepository,
    LogicalWorkSelectionStoreError, LogicalWorkflowInstanceId, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, LogicalWorkflowJobKind, ObjectKey, PinnedWorkflowRuntimePolicy,
    PublishLogicalJobActivation, QuarantineLogicalInstanceMaterialization,
    QuarantineLogicalJobOrchestration, RenewLogicalActivationPreparation,
    RenewLogicalInstanceMaterialization, RenewLogicalJobActivation,
    RenewedLogicalActivationPreparation, RenewedLogicalInstanceMaterialization,
    RenewedLogicalJobActivation, RepositoryId, SelectedLogicalInstanceMaterialization,
    SelectedLogicalJobOrchestration, StoreError, TenantScope, WorkflowRuntimePolicy,
    WorkflowRuntimePolicyPin, WorkflowRuntimePolicyRevision,
};
use automata_ci_workflow_service::{
    AdmissionClock, AutonomousActivationLease, AutonomousMaterializationLease,
    AutonomousPreparationLease, AutonomousWorkflowDeadline, AutonomousWorkflowError,
    AutonomousWorkflowExecutionFuture, AutonomousWorkflowExecutionOutcome,
    AutonomousWorkflowOutcome, AutonomousWorkflowPhase, AutonomousWorkflowPhaseExecutor,
    AutonomousWorkflowQueue, AutonomousWorkflowRenewalOutcome, AutonomousWorkflowService,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"contents":"read"},"write_all":{"contents":"write"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;
const TEST_CUSTODY_RETRY_MILLIS: u64 = 250;
const CUSTODY_SELECTION_SUBMISSION_CAP: usize = 121;

#[tokio::test]
async fn unpolled_ready_selections_are_drain_inert_in_both_queues() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let shutdown = CancellationToken::new();
    let clock = Arc::new(CancellingClock::new(shutdown.clone(), 1));
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let orchestration_service =
        service_with_clock(repository.clone(), executor.clone(), clock.clone());

    assert_eq!(
        orchestration_service
            .run_once(shutdown)
            .await
            .expect_err("cancellation before the first Store poll wins"),
        AutonomousWorkflowError::Shutdown,
    );
    assert!(repository.orchestration_selection_requests().is_empty());
    assert!(repository.orchestration_consume_requests().is_empty());
    assert_eq!(executor.io_count(), 0);
    assert_eq!(clock.calls(), 1);
    assert_eq!(
        orchestration_service
            .run_once(CancellationToken::new())
            .await
            .expect("the exact unsubmitted selection resumes live"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation),
    );
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
    assert_eq!(clock.calls(), 1, "resume must not construct a new request");

    let fixture = materialization_fixture(JobAuthorityProfile::Standard, 2, 1);
    let shutdown = CancellationToken::new();
    let clock = Arc::new(CancellingClock::new(shutdown.clone(), 2));
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(fixture.selected_outcome());
    repository.push_materialization_consume(fixture.consumed);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let materialization_service =
        service_with_clock(repository.clone(), executor.clone(), clock.clone());

    assert_eq!(
        materialization_service
            .run_once(shutdown)
            .await
            .expect_err("second-queue cancellation wins before Store polling"),
        AutonomousWorkflowError::Shutdown,
    );
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert!(repository.materialization_selection_requests().is_empty());
    assert!(repository.materialization_consume_requests().is_empty());
    assert_eq!(executor.io_count(), 0);
    assert_eq!(clock.calls(), 2);
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("the second queue resumes its exact unsubmitted selection"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization),
    );
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(repository.materialization_selection_requests().len(), 1);
    assert_eq!(repository.materialization_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
    assert_eq!(clock.calls(), 2, "resume must not rotate or rebuild");
}

#[tokio::test]
async fn select_cancellation_drains_only_to_selected_then_resumes_without_reselection() {
    let selected = preparation_fixture(JobAuthorityProfile::CredentialFree, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(selected.selected_outcome());
    repository.push_orchestration_consume(selected.consumed);
    repository.cancel_on_orchestration_select(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::OrchestrationSelect, 2);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = service(repository.clone(), executor.clone());

    let error = service
        .run_once(shutdown)
        .await
        .expect_err("selected evidence alone must not authorize work");

    assert_eq!(error, AutonomousWorkflowError::Shutdown);
    assert_eq!(repository.consume_count(), 0);
    assert_eq!(executor.io_count(), 0);
    assert_exact_replays(&repository.orchestration_selection_requests(), 4);

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("selected custody resumes"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_eq!(repository.consume_count(), 1);
    assert_eq!(repository.orchestration_selection_requests().len(), 4);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn cancellation_with_selected_response_never_submits_consume_during_drain() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    repository.cancel_after_orchestration_select_success(shutdown.clone());
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let orchestration_service = service(repository.clone(), executor.clone());

    assert_eq!(
        orchestration_service
            .run_once(shutdown)
            .await
            .expect_err("selection success observes the interstitial shutdown"),
        AutonomousWorkflowError::Shutdown,
    );
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert!(repository.orchestration_consume_requests().is_empty());
    assert_eq!(executor.io_count(), 0);
    assert_eq!(
        orchestration_service
            .run_once(CancellationToken::new())
            .await
            .expect("the retained orchestration selection resumes"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation),
    );
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    let fixture = materialization_fixture(JobAuthorityProfile::Standard, 1, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(fixture.selected_outcome());
    repository.push_materialization_consume(fixture.consumed);
    repository.cancel_after_materialization_select_success(shutdown.clone());
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let materialization_service = service(repository.clone(), executor.clone());

    assert_eq!(
        materialization_service
            .run_once(shutdown)
            .await
            .expect_err("materialization selection observes the interstitial shutdown"),
        AutonomousWorkflowError::Shutdown,
    );
    assert_eq!(repository.materialization_selection_requests().len(), 1);
    assert!(repository.materialization_consume_requests().is_empty());
    assert_eq!(executor.io_count(), 0);
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("the retained materialization selection resumes"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization),
    );
    assert_eq!(repository.materialization_selection_requests().len(), 1);
    assert_eq!(repository.materialization_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn consume_precedes_io_and_cancellation_after_consume_dominates_executor() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed.clone());
    repository.cancel_on_orchestration_consume(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::OrchestrationConsume, 2);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = service(repository.clone(), executor.clone());

    let error = service
        .run_once(shutdown)
        .await
        .expect_err("post-consume cancellation must dominate");

    assert_eq!(error, AutonomousWorkflowError::Shutdown);
    assert_eq!(executor.io_count(), 0);
    assert_eq!(
        repository.events(),
        vec![
            "select:o",
            "consume:o",
            "consume:o",
            "consume:o",
            "consume:o",
        ]
    );
    assert_exact_replays(&repository.orchestration_consume_requests(), 4);

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("active custody resumes"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_eq!(repository.orchestration_consume_requests().len(), 4);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn materialization_select_shutdown_retries_to_selected_without_consuming() {
    let selected = materialization_fixture(JobAuthorityProfile::Standard, 1, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(selected.selected_outcome());
    repository.push_materialization_consume(selected.consumed);
    repository.cancel_on_materialization_select(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::MaterializationSelect, 2);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = service(repository.clone(), executor.clone());

    assert_eq!(
        service
            .run_once(shutdown)
            .await
            .expect_err("selected evidence alone must not authorize materialization"),
        AutonomousWorkflowError::Shutdown
    );
    assert!(repository.materialization_consume_requests().is_empty());
    assert_eq!(executor.io_count(), 0);
    assert_exact_replays(&repository.materialization_selection_requests(), 4);

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("selected materialization custody resumes"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_eq!(repository.materialization_selection_requests().len(), 4);
    assert_eq!(repository.materialization_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn materialization_consume_shutdown_retries_to_active_without_executor_io() {
    let fixture = materialization_fixture(JobAuthorityProfile::Standard, 2, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(fixture.selected_outcome());
    repository.push_materialization_consume(fixture.consumed);
    repository.cancel_on_materialization_consume(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::MaterializationConsume, 2);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = service(repository.clone(), executor.clone());

    assert_eq!(
        service
            .run_once(shutdown)
            .await
            .expect_err("post-consume cancellation must dominate materialization"),
        AutonomousWorkflowError::Shutdown
    );
    assert_eq!(executor.io_count(), 0);
    assert_exact_replays(&repository.materialization_consume_requests(), 4);

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("active materialization custody resumes"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_eq!(repository.materialization_consume_requests().len(), 4);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn preparation_activation_and_materialization_are_separate_fair_passes() {
    let preparation = preparation_fixture(JobAuthorityProfile::CredentialFree, 1);
    let activation = activation_fixture(&preparation, 2, 1);
    let materialization = materialization_fixture(JobAuthorityProfile::Standard, 3, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(preparation.selected_outcome());
    repository.push_orchestration(activation.selected_outcome());
    repository.push_materialization(materialization.selected_outcome());
    repository.push_orchestration_consume(preparation.consumed);
    repository.push_orchestration_consume(activation.consumed);
    repository.push_materialization_consume(materialization.consumed);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = service(repository.clone(), executor.clone());

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("preparation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_eq!(
        executor.phases(),
        vec![AutonomousWorkflowPhase::Preparation]
    );
    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("materialization"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("activation"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Activation)
    );
    assert_eq!(
        executor.phases(),
        vec![
            AutonomousWorkflowPhase::Preparation,
            AutonomousWorkflowPhase::Materialization,
            AutonomousWorkflowPhase::Activation,
        ]
    );
    assert_eq!(executor.io_count(), 3);
}

#[tokio::test]
async fn successful_ack_rejects_base_consume_before_more_io_in_all_three_leases() {
    let preparation = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let activation = activation_fixture(&preparation, 2, 1);
    let materialization = materialization_fixture(JobAuthorityProfile::Standard, 3, 1);

    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(preparation.selected_outcome());
    repository.push_orchestration_consume(preparation.consumed.clone());
    repository.push_orchestration_consume(preparation.consumed);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let preparation_service = service(repository.clone(), executor.clone());
    assert_eq!(
        format!("{preparation_service:?}"),
        "AutonomousWorkflowService",
        "service Debug must expose only its type, never ports, worker IDs, or custody",
    );
    assert_eq!(
        preparation_service
            .run_once(CancellationToken::new())
            .await
            .expect_err("a preparation ACK cannot authorize its base predecessor"),
        AutonomousWorkflowError::AuthorityRejected,
    );
    assert!(executor.generations().is_empty());
    assert!(executor.renewals().is_empty());
    assert_eq!(executor.io_count(), 1);
    assert_eq!(
        executor.debug_types(),
        vec!["AutonomousPreparationLease", "AutonomousWorkflowDeadline",],
        "lease and deadline Debug must expose type names only",
    );
    assert_eq!(
        repository.events(),
        vec!["select:o", "consume:o", "renew:p:1", "consume:o"],
    );

    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(activation.selected_outcome());
    repository.push_orchestration_consume(activation.consumed.clone());
    repository.push_orchestration_consume(activation.consumed);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let activation_service = service(repository.clone(), executor.clone());
    assert_eq!(
        activation_service
            .run_once(CancellationToken::new())
            .await
            .expect_err("an activation ACK cannot authorize its base predecessor"),
        AutonomousWorkflowError::AuthorityRejected,
    );
    assert!(executor.generations().is_empty());
    assert!(executor.renewals().is_empty());
    assert_eq!(executor.io_count(), 1);
    assert_eq!(
        repository.events(),
        vec!["select:o", "consume:o", "renew:a:1", "consume:o"],
    );

    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(materialization.selected_outcome());
    repository.push_materialization_consume(materialization.consumed.clone());
    repository.push_materialization_consume(materialization.consumed);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let materialization_service = service(repository.clone(), executor.clone());
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect_err("a materialization ACK cannot authorize its base predecessor"),
        AutonomousWorkflowError::AuthorityRejected,
    );
    assert!(executor.generations().is_empty());
    assert!(executor.renewals().is_empty());
    assert_eq!(executor.io_count(), 1);
    assert_eq!(repository.materialization_consume_requests().len(), 2);
}

#[tokio::test]
async fn operation_renewal_reconsumes_same_selection_before_more_io() {
    let initial = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let current = initial.consumed.clone();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(initial.selected_outcome());
    repository.push_orchestration_consume(initial.consumed);
    repository.push_orchestration_consume(current);
    repository.ambiguous_next_preparation_renewal();
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let service = service(repository.clone(), executor.clone());

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("reconciled phase"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_eq!(
        executor.renewals(),
        vec![AutonomousWorkflowRenewalOutcome::Reconciled]
    );
    assert_eq!(executor.generations(), vec![1]);
    assert_eq!(executor.io_count(), 2);
    assert_eq!(
        repository.events(),
        vec!["select:o", "consume:o", "renew:p:1", "consume:o"]
    );
}

#[tokio::test]
async fn preparation_renewal_replay_operation_stops_drain_at_same_selected_authority() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed.clone());
    repository.push_orchestration_consume(fixture.consumed);
    repository.cancel_on_preparation_renewal(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::PreparationRenew, 1);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::RenewOnce));
    let service = service(repository.clone(), executor.clone());

    assert_eq!(
        service
            .run_once(shutdown)
            .await
            .expect_err("shutdown wins the in-flight preparation renewal"),
        AutonomousWorkflowError::Shutdown,
    );
    assert_one_exact_replay(&repository.preparation_renewal_requests());
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("the inert selection exact-consumes on a normal pass"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation),
    );
    assert_one_exact_replay(&repository.orchestration_consume_requests());
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(repository.preparation_renewal_requests().len(), 2);
    assert_eq!(executor.io_count(), 2);
}

#[tokio::test]
async fn activation_renewal_replay_operation_stops_drain_at_same_selected_authority() {
    let preparation = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let fixture = activation_fixture(&preparation, 2, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed.clone());
    repository.push_orchestration_consume(fixture.consumed);
    repository.cancel_on_activation_renewal(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::ActivationRenew, 1);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::RenewOnce));
    let service = service(repository.clone(), executor.clone());

    assert_eq!(
        service
            .run_once(shutdown)
            .await
            .expect_err("shutdown wins the in-flight activation renewal"),
        AutonomousWorkflowError::Shutdown,
    );
    assert_one_exact_replay(&repository.activation_renewal_requests());
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("the inert selection exact-consumes on a normal pass"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Activation),
    );
    assert_one_exact_replay(&repository.orchestration_consume_requests());
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(repository.activation_renewal_requests().len(), 2);
    assert_eq!(executor.io_count(), 2);
}

#[tokio::test]
async fn materialization_renewal_replay_operation_stops_drain_at_same_selected_authority() {
    let fixture = materialization_fixture(JobAuthorityProfile::Standard, 3, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(fixture.selected_outcome());
    repository.push_materialization_consume(fixture.consumed.clone());
    repository.push_materialization_consume(fixture.consumed);
    repository.cancel_on_materialization_renewal(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::MaterializationRenew, 1);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::RenewOnce));
    let service = service(repository.clone(), executor.clone());

    assert_eq!(
        service
            .run_once(shutdown)
            .await
            .expect_err("shutdown wins the in-flight materialization renewal"),
        AutonomousWorkflowError::Shutdown,
    );
    assert_one_exact_replay(&repository.materialization_renewal_requests());
    assert_eq!(repository.materialization_consume_requests().len(), 1);
    assert_eq!(repository.materialization_selection_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("the inert selection exact-consumes on a normal pass"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization),
    );
    assert_one_exact_replay(&repository.materialization_consume_requests());
    assert_eq!(repository.materialization_selection_requests().len(), 1);
    assert_eq!(repository.materialization_renewal_requests().len(), 2);
    assert_eq!(executor.io_count(), 2);
}

#[tokio::test]
async fn definitive_renewal_rejection_does_not_consume_again() {
    let initial = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(initial.selected_outcome());
    repository.push_orchestration_consume(initial.consumed);
    repository.malformed_next_preparation_renewal();
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let service = service(repository.clone(), executor.clone());

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect_err("definitive renewal rejection must fail closed"),
        AutonomousWorkflowError::AuthorityRejected
    );
    assert!(executor.renewals().is_empty());
    assert!(executor.generations().is_empty());
    assert_eq!(executor.io_count(), 1);
    assert_eq!(
        repository.events(),
        vec!["select:o", "consume:o", "renew:p:1"]
    );
}

#[tokio::test]
async fn quarantine_uses_latest_renewed_bundle_and_rejects_mismatch() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let reconciled = fixture.consumed.clone();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    repository.push_orchestration_consume(reconciled);
    repository.ambiguous_next_preparation_renewal();
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::RenewThenEvidence));
    let worker_service = service(repository.clone(), executor);

    assert_eq!(
        worker_service
            .run_once(CancellationToken::new())
            .await
            .expect("quarantine"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(repository.quarantined_generations(), vec![1]);

    let mismatch = preparation_fixture(JobAuthorityProfile::Standard, 1);
    repository.push_orchestration(mismatch.selected_outcome());
    repository.push_orchestration_consume(mismatch.consumed);
    repository.reject_next_quarantine();
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Evidence));
    let mismatch_service = service(repository, executor);
    assert_eq!(
        mismatch_service
            .run_once(CancellationToken::new())
            .await
            .expect_err("fence mismatch must fail closed"),
        AutonomousWorkflowError::QuarantineFenceRejected
    );
}

#[tokio::test(start_paused = true)]
async fn cumulative_deadline_is_checked_before_first_and_between_io() {
    let before_first = preparation_fixture_with_interval(
        JobAuthorityProfile::CredentialFree,
        1,
        1_000,
        3_000,
        2_000,
    );
    let slow_repository = Arc::new(FakeRepository::new());
    slow_repository.push_orchestration(before_first.selected_outcome());
    slow_repository.push_orchestration_consume(before_first.consumed);
    slow_repository.delay_next_orchestration_consume(Duration::from_millis(800));
    let untouched_executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let slow_service = service(slow_repository, untouched_executor.clone());
    assert_eq!(
        slow_service
            .run_once(CancellationToken::new())
            .await
            .expect("the consume round trip spends the same cumulative budget"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(untouched_executor.io_count(), 0);

    let fixture = preparation_fixture_with_interval(
        JobAuthorityProfile::CredentialFree,
        1,
        1_000,
        3_000,
        2_000,
    );
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::CrossDeadline));
    let service = service(repository, executor.clone());

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("deadline is a retryable unavailable classification"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn exact_quarantine_custody_can_finish_after_phase_deadline() {
    let fixture = preparation_fixture_with_interval(
        JobAuthorityProfile::CredentialFree,
        1,
        1_000,
        3_000,
        2_000,
    );
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    repository.delay_next_orchestration_quarantine(Duration::from_millis(100));
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::EvidenceNearDeadline));
    let service = service(repository.clone(), executor);

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("exact unsuperseded custody survives phase expiry"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(repository.quarantined_generations(), vec![1]);
}

#[tokio::test]
async fn durable_profile_not_visibility_drives_identical_worker_path() {
    let mut seen = Vec::new();
    for profile in [
        JobAuthorityProfile::CredentialFree,
        JobAuthorityProfile::Standard,
    ] {
        let fixture = preparation_fixture(profile, 1);
        let repository = Arc::new(FakeRepository::new());
        repository.push_orchestration(fixture.selected_outcome());
        repository.push_orchestration_consume(fixture.consumed);
        let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
        let service = service(repository, executor.clone());
        assert_eq!(
            service
                .run_once(CancellationToken::new())
                .await
                .expect("profile-agnostic pass"),
            AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
        );
        seen.extend(executor.profiles());
    }
    assert_eq!(
        seen,
        vec![
            JobAuthorityProfile::CredentialFree,
            JobAuthorityProfile::Standard,
        ]
    );
}

#[tokio::test]
async fn idle_contended_quarantined_and_unavailable_are_closed_results() {
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(LogicalJobOrchestrationSelectionOutcome::Contended);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = service(repository.clone(), executor);
    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("contended"),
        AutonomousWorkflowOutcome::Contended(AutonomousWorkflowQueue::Orchestration)
    );

    repository.push_materialization(LogicalInstanceMaterializationSelectionOutcome::Quarantined);
    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("quarantined"),
        AutonomousWorkflowOutcome::Quarantined(AutonomousWorkflowQueue::Materialization)
    );

    repository.fail_next_orchestration_selection();
    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("unavailable"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("idle"),
        AutonomousWorkflowOutcome::Idle
    );
}

#[tokio::test]
async fn selection_ambiguity_replays_exact_requests_before_rotation() {
    let orchestration = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(orchestration.selected_outcome());
    repository.push_orchestration_consume(orchestration.consumed);
    repository.fail_next_orchestration_selection();
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let orchestration_service = service(repository.clone(), executor.clone());

    assert_eq!(
        orchestration_service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous orchestration selection"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(
        orchestration_service
            .run_once(CancellationToken::new())
            .await
            .expect("exact orchestration selection replay"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_one_exact_replay(&repository.orchestration_selection_requests());
    assert_eq!(executor.io_count(), 1);

    let materialization = materialization_fixture(JobAuthorityProfile::Standard, 7, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(materialization.selected_outcome());
    repository.push_materialization_consume(materialization.consumed);
    repository.fail_next_materialization_selection();
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let materialization_service = service(repository.clone(), executor.clone());

    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous materialization selection"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Materialization)
    );
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("exact materialization selection replay"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_one_exact_replay(&repository.materialization_selection_requests());
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn consume_ambiguity_replays_exact_bundles_and_executes_once() {
    let orchestration = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(orchestration.selected_outcome());
    repository.push_orchestration_consume(orchestration.consumed);
    repository.fail_next_orchestration_consume();
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let orchestration_service = service(repository.clone(), executor.clone());

    assert_eq!(
        orchestration_service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous orchestration consume"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(executor.io_count(), 0);
    assert_eq!(
        orchestration_service
            .run_once(CancellationToken::new())
            .await
            .expect("exact orchestration consume replay"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_one_exact_replay(&repository.orchestration_consume_requests());
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    let materialization = materialization_fixture(JobAuthorityProfile::Standard, 8, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(materialization.selected_outcome());
    repository.push_materialization_consume(materialization.consumed);
    repository.fail_next_materialization_consume();
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let materialization_service = service(repository.clone(), executor.clone());

    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("ambiguous materialization consume"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Materialization)
    );
    assert_eq!(executor.io_count(), 0);
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("exact materialization consume replay"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    assert_one_exact_replay(&repository.materialization_consume_requests());
    assert_eq!(repository.materialization_selection_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn aborted_consume_resumes_before_another_selection_and_executes_once() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    repository.delay_next_orchestration_consume(Duration::from_mins(1));
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = Arc::new(service(repository.clone(), executor.clone()));
    let running = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.run_once(CancellationToken::new()).await })
    };

    tokio::time::timeout(Duration::from_secs(1), async {
        while repository.consume_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("consume starts");
    running.abort();
    assert!(running.await.expect_err("task was aborted").is_cancelled());

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("retained consume resumes"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_one_exact_replay(&repository.orchestration_consume_requests());
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn aborted_executor_future_retains_active_custody_for_exact_resume() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::BlockOnceAfterIo));
    let service = Arc::new(service(repository.clone(), executor.clone()));
    let running = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.run_once(CancellationToken::new()).await })
    };

    tokio::time::timeout(Duration::from_secs(1), async {
        while executor.io_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("executor starts with active custody");
    running.abort();
    assert!(running.await.expect_err("task was aborted").is_cancelled());

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("active authority resumes"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    assert_eq!(repository.orchestration_selection_requests().len(), 1);
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 2);
}

#[tokio::test]
async fn concurrent_run_once_calls_are_strictly_single_flight() {
    let repository = Arc::new(FakeRepository::new());
    repository.delay_next_orchestration_select(Duration::from_millis(50));
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = Arc::new(service(repository.clone(), executor));
    let first = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.run_once(CancellationToken::new()).await })
    };
    let second = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.run_once(CancellationToken::new()).await })
    };

    assert_eq!(
        first.await.expect("first joins").expect("first poll"),
        AutonomousWorkflowOutcome::Idle
    );
    assert_eq!(
        second.await.expect("second joins").expect("second poll"),
        AutonomousWorkflowOutcome::Idle
    );
    assert_eq!(repository.max_orchestration_select_in_flight(), 1);
}

#[tokio::test]
async fn value_only_final_markers_cannot_advance_without_queue_custody() {
    for mode in [
        ExecutorMode::UnboundFinalReadyOnce,
        ExecutorMode::UnboundFinalOperationOnce,
    ] {
        let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
        let repository = Arc::new(FakeRepository::new());
        repository.push_orchestration(fixture.selected_outcome());
        repository.push_orchestration_consume(fixture.consumed);
        let executor = Arc::new(FakeExecutor::new(mode));
        let service = service(repository.clone(), executor.clone());

        assert_eq!(
            service
                .run_once(CancellationToken::new())
                .await
                .expect_err("a value-only final marker has no authority"),
            AutonomousWorkflowError::AuthorityRejected,
        );
        assert_eq!(
            service
                .run_once(CancellationToken::new())
                .await
                .expect("the exact active bundle remains resumable"),
            AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation),
        );
        assert_eq!(repository.orchestration_selection_requests().len(), 1);
        assert_eq!(repository.orchestration_consume_requests().len(), 1);
        assert_eq!(executor.io_count(), 2);
    }
}

#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)] // Covers both queues and all three typed renewal paths explicitly.
async fn expired_selected_and_renewal_ack_at_deadline_never_start_new_io() {
    let initial = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(initial.selected_outcome());
    repository.push_orchestration_consume(initial.consumed);
    repository.cancel_on_preparation_renewal(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::PreparationRenew, 1);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let preparation_service = service(repository.clone(), executor.clone());
    assert_eq!(
        preparation_service
            .run_once(shutdown)
            .await
            .expect_err("preparation renewal cancellation"),
        AutonomousWorkflowError::Shutdown
    );
    assert_one_exact_replay(&repository.preparation_renewal_requests());
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        preparation_service
            .run_once(CancellationToken::new())
            .await
            .expect("expired selected preparation custody closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    let preparation = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let initial = activation_fixture(&preparation, 11, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(initial.selected_outcome());
    repository.push_orchestration_consume(initial.consumed);
    repository.cancel_on_activation_renewal(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::ActivationRenew, 1);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let activation_service = service(repository.clone(), executor.clone());
    assert_eq!(
        activation_service
            .run_once(shutdown)
            .await
            .expect_err("activation renewal cancellation"),
        AutonomousWorkflowError::Shutdown
    );
    assert_one_exact_replay(&repository.activation_renewal_requests());
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        activation_service
            .run_once(CancellationToken::new())
            .await
            .expect("expired selected activation custody closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    let initial = materialization_fixture(JobAuthorityProfile::Standard, 12, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(initial.selected_outcome());
    repository.push_materialization_consume(initial.consumed);
    repository.cancel_on_materialization_renewal(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::MaterializationRenew, 1);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let materialization_service = service(repository.clone(), executor.clone());
    assert_eq!(
        materialization_service
            .run_once(shutdown)
            .await
            .expect_err("materialization renewal cancellation"),
        AutonomousWorkflowError::Shutdown
    );
    assert_one_exact_replay(&repository.materialization_renewal_requests());
    assert_eq!(repository.materialization_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("expired selected materialization custody closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Materialization)
    );
    assert_eq!(repository.materialization_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    let initial = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(initial.selected_outcome());
    repository.push_orchestration_consume(initial.consumed);
    repository.delay_next_preparation_renewal(Duration::from_mins(10));
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let preparation_service = Arc::new(service(repository.clone(), executor.clone()));
    let running = {
        let service = Arc::clone(&preparation_service);
        tokio::spawn(async move { service.run_once(CancellationToken::new()).await })
    };
    while repository.preparation_renewal_requests().is_empty() {
        tokio::task::yield_now().await;
    }
    running.abort();
    assert!(running.await.expect_err("task was aborted").is_cancelled());
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        preparation_service
            .run_once(CancellationToken::new())
            .await
            .expect("preparation ACK at the deadline closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_one_exact_replay(&repository.preparation_renewal_requests());
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    let preparation = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let initial = activation_fixture(&preparation, 14, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(initial.selected_outcome());
    repository.push_orchestration_consume(initial.consumed);
    repository.delay_next_activation_renewal(Duration::from_mins(10));
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let activation_service = Arc::new(service(repository.clone(), executor.clone()));
    let running = {
        let service = Arc::clone(&activation_service);
        tokio::spawn(async move { service.run_once(CancellationToken::new()).await })
    };
    while repository.activation_renewal_requests().is_empty() {
        tokio::task::yield_now().await;
    }
    running.abort();
    assert!(running.await.expect_err("task was aborted").is_cancelled());
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        activation_service
            .run_once(CancellationToken::new())
            .await
            .expect("activation ACK at the deadline closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Orchestration)
    );
    assert_one_exact_replay(&repository.activation_renewal_requests());
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);

    let initial = materialization_fixture(JobAuthorityProfile::Standard, 15, 1);
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(initial.selected_outcome());
    repository.push_materialization_consume(initial.consumed);
    repository.delay_next_materialization_renewal(Duration::from_mins(10));
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Renew));
    let materialization_service = Arc::new(service(repository.clone(), executor.clone()));
    let running = {
        let service = Arc::clone(&materialization_service);
        tokio::spawn(async move { service.run_once(CancellationToken::new()).await })
    };
    while repository.materialization_renewal_requests().is_empty() {
        tokio::task::yield_now().await;
    }
    running.abort();
    assert!(running.await.expect_err("task was aborted").is_cancelled());
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        materialization_service
            .run_once(CancellationToken::new())
            .await
            .expect("materialization ACK at the deadline closes"),
        AutonomousWorkflowOutcome::Unavailable(AutonomousWorkflowQueue::Materialization)
    );
    assert_one_exact_replay(&repository.materialization_renewal_requests());
    assert_eq!(repository.materialization_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test]
async fn shutdown_replays_both_quarantines_without_restarting_executor_io() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    repository.cancel_on_orchestration_quarantine(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::OrchestrationQuarantine, 2);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Evidence));
    let orchestration_service = service(repository.clone(), executor.clone());
    assert_eq!(
        orchestration_service
            .run_once(shutdown)
            .await
            .expect_err("orchestration quarantine cancellation"),
        AutonomousWorkflowError::Shutdown
    );
    assert_exact_replays(&repository.orchestration_quarantine_requests(), 4);
    assert_eq!(executor.io_count(), 1);

    let fixture = materialization_fixture(JobAuthorityProfile::Standard, 13, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(fixture.selected_outcome());
    repository.push_materialization_consume(fixture.consumed);
    repository.cancel_on_materialization_quarantine(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::MaterializationQuarantine, 2);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Evidence));
    let materialization_service = service(repository.clone(), executor.clone());
    assert_eq!(
        materialization_service
            .run_once(shutdown)
            .await
            .expect_err("materialization quarantine cancellation"),
        AutonomousWorkflowError::Shutdown
    );
    assert_exact_replays(&repository.materialization_quarantine_requests(), 4);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn orchestration_shutdown_drain_has_one_absolute_timeout_and_retains_custody() {
    let fixture = preparation_fixture(JobAuthorityProfile::Standard, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_orchestration(fixture.selected_outcome());
    repository.push_orchestration_consume(fixture.consumed);
    repository.cancel_on_orchestration_select(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::OrchestrationSelect, usize::MAX);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = Arc::new(service(repository.clone(), executor.clone()));
    let running = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.run_once(shutdown).await })
    };

    while repository.orchestration_selection_requests().len() < 2 {
        tokio::task::yield_now().await;
    }
    assert_bounded_custody_attempts(|| repository.orchestration_selection_requests().len()).await;
    assert!(
        !running.is_finished(),
        "drain stopped before its fixed bound"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..100 {
        if running.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(running.is_finished(), "drain exceeded its fixed bound");
    assert_eq!(
        running
            .await
            .expect("shutdown task joins")
            .expect_err("shutdown still dominates a timed-out drain"),
        AutonomousWorkflowError::Shutdown
    );
    assert!(repository.orchestration_consume_requests().is_empty());
    assert_eq!(executor.io_count(), 0);
    let timed_out_requests = repository.orchestration_selection_requests();
    assert_exact_replays(&timed_out_requests, CUSTODY_SELECTION_SUBMISSION_CAP);

    repository.fail_replayed_operations(FakeRepositoryOperation::OrchestrationSelect, 0);
    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("retained selection custody resumes after shutdown"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Preparation)
    );
    let completed_requests = repository.orchestration_selection_requests();
    assert_eq!(completed_requests.len(), timed_out_requests.len() + 1);
    assert_exact_replays(&completed_requests, completed_requests.len());
    assert_eq!(repository.orchestration_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn materialization_shutdown_drain_has_one_absolute_timeout_and_retains_custody() {
    let fixture = materialization_fixture(JobAuthorityProfile::Standard, 16, 1);
    let shutdown = CancellationToken::new();
    let repository = Arc::new(FakeRepository::new());
    repository.push_materialization(fixture.selected_outcome());
    repository.push_materialization_consume(fixture.consumed);
    repository.cancel_on_materialization_select(shutdown.clone());
    repository.fail_replayed_operations(FakeRepositoryOperation::MaterializationSelect, usize::MAX);
    let executor = Arc::new(FakeExecutor::new(ExecutorMode::Complete));
    let service = Arc::new(service(repository.clone(), executor.clone()));
    let running = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.run_once(shutdown).await })
    };

    while repository.materialization_selection_requests().len() < 2 {
        tokio::task::yield_now().await;
    }
    assert_bounded_custody_attempts(|| repository.materialization_selection_requests().len()).await;
    assert!(
        !running.is_finished(),
        "drain stopped before its fixed bound"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..100 {
        if running.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(running.is_finished(), "drain exceeded its fixed bound");
    assert_eq!(
        running
            .await
            .expect("shutdown task joins")
            .expect_err("shutdown still dominates a timed-out drain"),
        AutonomousWorkflowError::Shutdown
    );
    assert!(repository.materialization_consume_requests().is_empty());
    assert_eq!(executor.io_count(), 0);
    let timed_out_requests = repository.materialization_selection_requests();
    assert_exact_replays(&timed_out_requests, CUSTODY_SELECTION_SUBMISSION_CAP);

    repository.fail_replayed_operations(FakeRepositoryOperation::MaterializationSelect, 0);
    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("retained materialization selection resumes after shutdown"),
        AutonomousWorkflowOutcome::Completed(AutonomousWorkflowPhase::Materialization)
    );
    let completed_requests = repository.materialization_selection_requests();
    assert_eq!(completed_requests.len(), timed_out_requests.len() + 1);
    assert_exact_replays(&completed_requests, completed_requests.len());
    assert_eq!(repository.materialization_consume_requests().len(), 1);
    assert_eq!(executor.io_count(), 1);
}

async fn assert_bounded_custody_attempts(request_count: impl Fn() -> usize) {
    assert_eq!(request_count(), 2, "the drain starts one immediate replay");
    for expected in 3..=CUSTODY_SELECTION_SUBMISSION_CAP {
        tokio::time::advance(Duration::from_millis(TEST_CUSTODY_RETRY_MILLIS)).await;
        tokio::task::yield_now().await;
        assert_eq!(request_count(), expected, "one replay per cadence");
    }
    tokio::time::advance(Duration::from_millis(TEST_CUSTODY_RETRY_MILLIS - 1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        request_count(),
        CUSTODY_SELECTION_SUBMISSION_CAP,
        "no replay starts between cadence boundaries",
    );
}

fn assert_one_exact_replay<T>(requests: &[T])
where
    T: std::fmt::Debug + PartialEq,
{
    assert_exact_replays(requests, 2);
}

fn assert_exact_replays<T>(requests: &[T], expected_submissions: usize)
where
    T: std::fmt::Debug + PartialEq,
{
    assert_eq!(requests.len(), expected_submissions);
    assert!(
        requests.windows(2).all(|pair| pair[0] == pair[1]),
        "every replay must preserve every field: {requests:?}",
    );
}

#[derive(Clone)]
struct OrchestrationFixture {
    selected: SelectedLogicalJobOrchestration,
    consumed: ConsumedSelectedLogicalJobOrchestration,
}

impl OrchestrationFixture {
    fn selected_outcome(&self) -> LogicalJobOrchestrationSelectionOutcome {
        LogicalJobOrchestrationSelectionOutcome::Selected(self.selected.clone())
    }
}

#[derive(Clone)]
struct MaterializationFixture {
    selected: SelectedLogicalInstanceMaterialization,
    consumed: ConsumedSelectedLogicalInstanceMaterialization,
}

impl MaterializationFixture {
    fn selected_outcome(&self) -> LogicalInstanceMaterializationSelectionOutcome {
        LogicalInstanceMaterializationSelectionOutcome::Selected(self.selected.clone())
    }
}

fn preparation_fixture(profile: JobAuthorityProfile, generation: u64) -> OrchestrationFixture {
    let offset = i64::try_from(generation.saturating_sub(1)).expect("generation offset");
    preparation_fixture_with_interval(
        profile,
        generation,
        1_000 + offset,
        301_000 + offset,
        1_000 + offset,
    )
}

fn preparation_fixture_with_interval(
    profile: JobAuthorityProfile,
    generation: u64,
    claimed_at: i64,
    expires_at: i64,
    validated_at: i64,
) -> OrchestrationFixture {
    let descriptor = preparation_descriptor(profile);
    let selection_id = selection_id(40);
    let worker = orchestration_worker();
    let (selected_claimed_at, selected_expires_at) = if generation == 1 {
        (claimed_at, expires_at)
    } else {
        (1_000, 301_000)
    };
    let selected = SelectedLogicalJobOrchestration::new(
        selection_id,
        descriptor.target().clone(),
        worker,
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        LogicalJobOrchestrationAuthorityKind::Preparation,
        descriptor.descriptor_digest(),
        UnixMillis::new(selected_claimed_at),
        UnixMillis::new(selected_expires_at),
    )
    .expect("selected preparation");
    let fence = LogicalActivationPreparationClaimFence::new_for_selection(
        descriptor.target().clone(),
        worker,
        LogicalActivationPreparationGeneration::new(generation).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
        selection_id,
    )
    .expect("preparation fence");
    let authority = ClaimedLogicalActivationPreparation::new(descriptor, fence, false)
        .expect("preparation authority");
    let consumed = ConsumedSelectedLogicalJobOrchestration::new(
        selected.clone(),
        ConsumedLogicalJobOrchestrationAuthority::Preparation(authority),
        UnixMillis::new(validated_at),
    )
    .expect("consumed preparation");
    OrchestrationFixture { selected, consumed }
}

fn activation_fixture(
    preparation: &OrchestrationFixture,
    selection_number: u128,
    generation: u64,
) -> OrchestrationFixture {
    let ConsumedLogicalJobOrchestrationAuthority::Preparation(prepared) =
        preparation.consumed.authority()
    else {
        panic!("preparation fixture");
    };
    let descriptor = prepared.descriptor();
    let target = descriptor.target();
    let selection_id = selection_id(40 + selection_number);
    let input_digest = Sha256Digest::from_bytes([0x77; 32]);
    let authority_offset = i64::try_from(generation.saturating_sub(1)).expect("generation offset");
    let selected = SelectedLogicalJobOrchestration::new(
        selection_id,
        target.clone(),
        orchestration_worker(),
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        LogicalJobOrchestrationAuthorityKind::Activation,
        input_digest,
        UnixMillis::new(1_000),
        UnixMillis::new(301_000),
    )
    .expect("selected activation");
    let fence = LogicalActivationClaimFence::new_for_selection(
        target.tenant().clone(),
        target.run_id(),
        target.invocation_id(),
        target.logical_job_id(),
        orchestration_worker(),
        descriptor.runtime_policy().pin().clone(),
        LogicalActivationGeneration::new(generation).expect("generation"),
        input_digest,
        UnixMillis::new(1_000 + authority_offset),
        UnixMillis::new(301_000 + authority_offset),
        selection_id,
    )
    .expect("activation fence");
    let authority = ClaimedLogicalJobActivation::new(
        fence,
        descriptor.logical_key().clone(),
        descriptor.source_order(),
        LogicalWorkflowJobKind::Steps,
        descriptor.execution().clone(),
        descriptor.plan().clone(),
        descriptor.event().clone(),
        false,
    )
    .expect("activation authority");
    let consumed = ConsumedSelectedLogicalJobOrchestration::new(
        selected.clone(),
        ConsumedLogicalJobOrchestrationAuthority::Activation(authority),
        UnixMillis::new(1_000 + authority_offset),
    )
    .expect("consumed activation");
    OrchestrationFixture { selected, consumed }
}

fn materialization_fixture(
    profile: JobAuthorityProfile,
    selection_number: u128,
    generation: u64,
) -> MaterializationFixture {
    let prepared = preparation_descriptor(profile);
    let target = LogicalInstanceMaterializationTarget::new(
        prepared.target().tenant().clone(),
        prepared.target().run_id(),
        prepared.target().invocation_id(),
        prepared.target().logical_job_id(),
        LogicalWorkflowInstanceId::from_uuid(Uuid::from_u128(90)).expect("instance"),
    )
    .expect("materialization target");
    let descriptor = LogicalInstanceMaterializationDescriptor::new(
        target.clone(),
        prepared.logical_key().clone(),
        0,
        1,
        Sha256Digest::from_bytes([0x55; 32]),
        prepared.workspace().as_str().to_owned(),
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes([0x61; 32]),
            ObjectKey::new("jobs/one.pb").expect("job object key"),
            128,
        )
        .expect("job object"),
        LogicalActivationObject::runtime_context(
            Sha256Digest::from_bytes([0x62; 32]),
            ObjectKey::new("contexts/one.pb").expect("context object key"),
            128,
        )
        .expect("runtime object"),
        prepared.event().clone(),
        prepared.execution().clone(),
        profile,
        prepared.runtime_policy().pin().clone(),
    )
    .expect("materialization descriptor");
    let selection_id = selection_id(70 + selection_number);
    let authority_offset = i64::try_from(generation.saturating_sub(1)).expect("generation offset");
    let selected = SelectedLogicalInstanceMaterialization::new(
        selection_id,
        target,
        materialization_worker(),
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(1_000),
        UnixMillis::new(301_000),
    )
    .expect("selected materialization");
    let fence = LogicalMaterializationClaimFence::new_for_selection(
        descriptor.target().clone(),
        materialization_worker(),
        LogicalMaterializationGeneration::new(generation).expect("generation"),
        descriptor.descriptor_digest(),
        descriptor.runtime_policy().clone(),
        descriptor.expected_job_id(),
        descriptor.expected_attempt_id(),
        UnixMillis::new(1_000 + authority_offset),
        UnixMillis::new(301_000 + authority_offset),
        selection_id,
    )
    .expect("materialization fence");
    let authority = ClaimedLogicalInstanceMaterialization::new(descriptor, fence, false)
        .expect("materialization authority");
    let consumed = ConsumedSelectedLogicalInstanceMaterialization::new(
        selected.clone(),
        authority,
        UnixMillis::new(1_000 + authority_offset),
    )
    .expect("consumed materialization");
    MaterializationFixture { selected, consumed }
}

fn preparation_descriptor(profile: JobAuthorityProfile) -> LogicalActivationPreparationDescriptor {
    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        RunId::from_uuid(Uuid::from_u128(1)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(3)).expect("logical job"),
    )
    .expect("preparation target");
    let policy = WorkflowRuntimePolicy::decode_configuration(RUNTIME_POLICY).expect("policy");
    let canonical = policy.canonical_bytes().expect("canonical policy");
    let canonical_digest = policy.canonical_digest();
    let runner_policy = AdmissionObject::new(
        canonical_digest,
        ObjectKey::new(format!("github/runner-policy/v1/{canonical_digest}.json"))
            .expect("runner-policy key"),
        u64::try_from(canonical.len()).expect("runner-policy size"),
        GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
    )
    .expect("runner policy");
    let pin = WorkflowRuntimePolicyPin::new(
        target.tenant().clone(),
        RepositoryId::from_uuid(Uuid::from_u128(5)),
        WorkflowRuntimePolicyRevision::new(1).expect("revision"),
        policy.digest(),
    );
    let pinned = PinnedWorkflowRuntimePolicy::new(target.run_id(), pin, policy).expect("pin");
    LogicalActivationPreparationDescriptor::new(
        target,
        WorkflowJobKey::new("build").expect("logical key"),
        0,
        LogicalActivationExecutionContext::new(
            WorkflowId::from_uuid(Uuid::from_u128(6)),
            "CI".to_owned(),
            "refs/heads/main".to_owned(),
            "push".to_owned(),
            Some("octocat".to_owned()),
            RunIdAlias::new(11).expect("run ID alias"),
            1,
            1,
        )
        .expect("execution"),
        profile,
        runner_policy,
        pinned,
        admission_object(
            "plans/current.json",
            0x21,
            LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE,
        ),
        admission_object(
            "events/current.json",
            0x22,
            LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE,
        ),
        LogicalActivationBaseContextKind::Admission,
        admission_object(
            "contexts/base.pb",
            0x23,
            automata_ci_store::LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
        ),
        Vec::new(),
        UnixMillis::new(10),
    )
    .expect("preparation descriptor")
}

fn admission_object(key: &str, digest: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("object key"),
        128,
        media_type,
    )
    .expect("admission object")
}

fn selection_id(value: u128) -> LogicalWorkSelectionId {
    LogicalWorkSelectionId::from_uuid(Uuid::from_u128(value)).expect("selection ID")
}

fn orchestration_worker() -> LogicalActivationWorkerId {
    LogicalActivationWorkerId::from_uuid(Uuid::from_u128(20)).expect("orchestration worker")
}

fn materialization_worker() -> LogicalMaterializationWorkerId {
    LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(21)).expect("materialization worker")
}

#[derive(Debug)]
struct FixedClock;

impl AdmissionClock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(1_000)
    }
}

#[derive(Debug)]
struct CancellingClock {
    shutdown: CancellationToken,
    cancel_on_call: usize,
    calls: AtomicUsize,
}

impl CancellingClock {
    fn new(shutdown: CancellationToken, cancel_on_call: usize) -> Self {
        Self {
            shutdown,
            cancel_on_call,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl AdmissionClock for CancellingClock {
    fn now(&self) -> UnixMillis {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.cancel_on_call {
            self.shutdown.cancel();
        }
        UnixMillis::new(1_000)
    }
}

fn service(
    repository: Arc<FakeRepository>,
    executor: Arc<FakeExecutor>,
) -> AutonomousWorkflowService {
    service_with_clock(repository, executor, Arc::new(FixedClock))
}

fn service_with_clock(
    repository: Arc<FakeRepository>,
    executor: Arc<FakeExecutor>,
    clock: Arc<dyn AdmissionClock>,
) -> AutonomousWorkflowService {
    AutonomousWorkflowService::new(
        repository.clone(),
        repository.clone(),
        repository.clone(),
        repository,
        executor,
        clock,
        orchestration_worker(),
        materialization_worker(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeRepositoryOperation {
    OrchestrationSelect,
    MaterializationSelect,
    OrchestrationConsume,
    MaterializationConsume,
    PreparationRenew,
    ActivationRenew,
    MaterializationRenew,
    OrchestrationQuarantine,
    MaterializationQuarantine,
}

impl FakeRepositoryOperation {
    const COUNT: usize = 9;

    const fn index(self) -> usize {
        match self {
            Self::OrchestrationSelect => 0,
            Self::MaterializationSelect => 1,
            Self::OrchestrationConsume => 2,
            Self::MaterializationConsume => 3,
            Self::PreparationRenew => 4,
            Self::ActivationRenew => 5,
            Self::MaterializationRenew => 6,
            Self::OrchestrationQuarantine => 7,
            Self::MaterializationQuarantine => 8,
        }
    }
}

#[derive(Debug)]
struct FakeRepository {
    state: Mutex<FakeRepositoryState>,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent one-shot fault switches script exact races.
struct FakeRepositoryState {
    orchestration: VecDeque<LogicalJobOrchestrationSelectionOutcome>,
    materialization: VecDeque<LogicalInstanceMaterializationSelectionOutcome>,
    orchestration_consumes: VecDeque<ConsumedSelectedLogicalJobOrchestration>,
    materialization_consumes: VecDeque<ConsumedSelectedLogicalInstanceMaterialization>,
    orchestration_selection_replay: Option<(
        ClaimNextLogicalJobOrchestration,
        LogicalJobOrchestrationSelectionOutcome,
    )>,
    materialization_selection_replay: Option<(
        ClaimNextLogicalInstanceMaterialization,
        LogicalInstanceMaterializationSelectionOutcome,
    )>,
    orchestration_consume_replay: Option<(
        ConsumeSelectedLogicalJobOrchestration,
        ConsumedSelectedLogicalJobOrchestration,
    )>,
    materialization_consume_replay: Option<(
        ConsumeSelectedLogicalInstanceMaterialization,
        ConsumedSelectedLogicalInstanceMaterialization,
    )>,
    preparation_renewal_replay: Option<(
        RenewLogicalActivationPreparation,
        RenewedLogicalActivationPreparation,
    )>,
    activation_renewal_replay: Option<(RenewLogicalJobActivation, RenewedLogicalJobActivation)>,
    materialization_renewal_replay: Option<(
        RenewLogicalInstanceMaterialization,
        RenewedLogicalInstanceMaterialization,
    )>,
    orchestration_quarantine_replay: Option<(
        QuarantineLogicalJobOrchestration,
        LogicalWorkQuarantineOutcome,
    )>,
    materialization_quarantine_replay: Option<(
        QuarantineLogicalInstanceMaterialization,
        LogicalWorkQuarantineOutcome,
    )>,
    orchestration_selection_requests: Vec<ClaimNextLogicalJobOrchestration>,
    materialization_selection_requests: Vec<ClaimNextLogicalInstanceMaterialization>,
    orchestration_consume_requests: Vec<ConsumeSelectedLogicalJobOrchestration>,
    materialization_consume_requests: Vec<ConsumeSelectedLogicalInstanceMaterialization>,
    preparation_renewal_requests: Vec<RenewLogicalActivationPreparation>,
    activation_renewal_requests: Vec<RenewLogicalJobActivation>,
    materialization_renewal_requests: Vec<RenewLogicalInstanceMaterialization>,
    orchestration_quarantine_requests: Vec<QuarantineLogicalJobOrchestration>,
    materialization_quarantine_requests: Vec<QuarantineLogicalInstanceMaterialization>,
    events: Vec<&'static str>,
    cancel_on_orchestration_select: Option<CancellationToken>,
    cancel_on_materialization_select: Option<CancellationToken>,
    cancel_after_orchestration_select_success: Option<CancellationToken>,
    cancel_after_materialization_select_success: Option<CancellationToken>,
    cancel_on_orchestration_consume: Option<CancellationToken>,
    cancel_on_materialization_consume: Option<CancellationToken>,
    cancel_on_preparation_renewal: Option<CancellationToken>,
    cancel_on_activation_renewal: Option<CancellationToken>,
    cancel_on_materialization_renewal: Option<CancellationToken>,
    delay_next_preparation_renewal: Option<Duration>,
    delay_next_activation_renewal: Option<Duration>,
    delay_next_materialization_renewal: Option<Duration>,
    cancel_on_orchestration_quarantine: Option<CancellationToken>,
    cancel_on_materialization_quarantine: Option<CancellationToken>,
    delay_next_orchestration_select: Option<Duration>,
    delay_next_orchestration_consume: Option<Duration>,
    delay_next_orchestration_quarantine: Option<Duration>,
    fail_next_orchestration_selection: bool,
    fail_next_materialization_selection: bool,
    fail_next_orchestration_consume: bool,
    fail_next_materialization_consume: bool,
    ambiguous_next_preparation_renewal: bool,
    malformed_next_preparation_renewal: bool,
    reject_next_quarantine: bool,
    quarantined_generations: Vec<u64>,
    replay_operation_failures: [usize; FakeRepositoryOperation::COUNT],
    track_orchestration_select_concurrency: bool,
    orchestration_select_in_flight: usize,
    max_orchestration_select_in_flight: usize,
}

impl FakeRepositoryState {
    fn take_replay_operation_failure(&mut self, operation: FakeRepositoryOperation) -> bool {
        let remaining = &mut self.replay_operation_failures[operation.index()];
        if *remaining == 0 {
            false
        } else {
            *remaining -= 1;
            true
        }
    }
}

impl FakeRepository {
    fn new() -> Self {
        Self {
            state: Mutex::new(FakeRepositoryState {
                orchestration: VecDeque::new(),
                materialization: VecDeque::new(),
                orchestration_consumes: VecDeque::new(),
                materialization_consumes: VecDeque::new(),
                orchestration_selection_replay: None,
                materialization_selection_replay: None,
                orchestration_consume_replay: None,
                materialization_consume_replay: None,
                preparation_renewal_replay: None,
                activation_renewal_replay: None,
                materialization_renewal_replay: None,
                orchestration_quarantine_replay: None,
                materialization_quarantine_replay: None,
                orchestration_selection_requests: Vec::new(),
                materialization_selection_requests: Vec::new(),
                orchestration_consume_requests: Vec::new(),
                materialization_consume_requests: Vec::new(),
                preparation_renewal_requests: Vec::new(),
                activation_renewal_requests: Vec::new(),
                materialization_renewal_requests: Vec::new(),
                orchestration_quarantine_requests: Vec::new(),
                materialization_quarantine_requests: Vec::new(),
                events: Vec::new(),
                cancel_on_orchestration_select: None,
                cancel_on_materialization_select: None,
                cancel_after_orchestration_select_success: None,
                cancel_after_materialization_select_success: None,
                cancel_on_orchestration_consume: None,
                cancel_on_materialization_consume: None,
                cancel_on_preparation_renewal: None,
                cancel_on_activation_renewal: None,
                cancel_on_materialization_renewal: None,
                delay_next_preparation_renewal: None,
                delay_next_activation_renewal: None,
                delay_next_materialization_renewal: None,
                cancel_on_orchestration_quarantine: None,
                cancel_on_materialization_quarantine: None,
                delay_next_orchestration_select: None,
                delay_next_orchestration_consume: None,
                delay_next_orchestration_quarantine: None,
                fail_next_orchestration_selection: false,
                fail_next_materialization_selection: false,
                fail_next_orchestration_consume: false,
                fail_next_materialization_consume: false,
                ambiguous_next_preparation_renewal: false,
                malformed_next_preparation_renewal: false,
                reject_next_quarantine: false,
                quarantined_generations: Vec::new(),
                replay_operation_failures: [0; FakeRepositoryOperation::COUNT],
                track_orchestration_select_concurrency: false,
                orchestration_select_in_flight: 0,
                max_orchestration_select_in_flight: 0,
            }),
        }
    }

    fn push_orchestration(&self, outcome: LogicalJobOrchestrationSelectionOutcome) {
        self.state
            .lock()
            .expect("state")
            .orchestration
            .push_back(outcome);
    }

    fn push_materialization(&self, outcome: LogicalInstanceMaterializationSelectionOutcome) {
        self.state
            .lock()
            .expect("state")
            .materialization
            .push_back(outcome);
    }

    fn push_orchestration_consume(&self, consumed: ConsumedSelectedLogicalJobOrchestration) {
        self.state
            .lock()
            .expect("state")
            .orchestration_consumes
            .push_back(consumed);
    }

    fn push_materialization_consume(
        &self,
        consumed: ConsumedSelectedLogicalInstanceMaterialization,
    ) {
        self.state
            .lock()
            .expect("state")
            .materialization_consumes
            .push_back(consumed);
    }

    fn cancel_on_orchestration_select(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_orchestration_select = Some(shutdown);
    }

    fn cancel_on_materialization_select(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_materialization_select = Some(shutdown);
    }

    fn cancel_after_orchestration_select_success(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_after_orchestration_select_success = Some(shutdown);
    }

    fn cancel_after_materialization_select_success(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_after_materialization_select_success = Some(shutdown);
    }

    fn cancel_on_orchestration_consume(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_orchestration_consume = Some(shutdown);
    }

    fn cancel_on_materialization_consume(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_materialization_consume = Some(shutdown);
    }

    fn fail_replayed_operations(&self, operation: FakeRepositoryOperation, count: usize) {
        self.state.lock().expect("state").replay_operation_failures[operation.index()] = count;
    }

    fn fail_next_orchestration_selection(&self) {
        self.state
            .lock()
            .expect("state")
            .fail_next_orchestration_selection = true;
    }

    fn fail_next_materialization_selection(&self) {
        self.state
            .lock()
            .expect("state")
            .fail_next_materialization_selection = true;
    }

    fn fail_next_orchestration_consume(&self) {
        self.state
            .lock()
            .expect("state")
            .fail_next_orchestration_consume = true;
    }

    fn fail_next_materialization_consume(&self) {
        self.state
            .lock()
            .expect("state")
            .fail_next_materialization_consume = true;
    }

    fn delay_next_orchestration_select(&self, duration: Duration) {
        let mut state = self.state.lock().expect("state");
        state.delay_next_orchestration_select = Some(duration);
        state.track_orchestration_select_concurrency = true;
    }

    fn delay_next_orchestration_consume(&self, duration: Duration) {
        self.state
            .lock()
            .expect("state")
            .delay_next_orchestration_consume = Some(duration);
    }

    fn malformed_next_preparation_renewal(&self) {
        self.state
            .lock()
            .expect("state")
            .malformed_next_preparation_renewal = true;
    }

    fn ambiguous_next_preparation_renewal(&self) {
        self.state
            .lock()
            .expect("state")
            .ambiguous_next_preparation_renewal = true;
    }

    fn cancel_on_preparation_renewal(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_preparation_renewal = Some(shutdown);
    }

    fn cancel_on_activation_renewal(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_activation_renewal = Some(shutdown);
    }

    fn cancel_on_materialization_renewal(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_materialization_renewal = Some(shutdown);
    }

    fn delay_next_preparation_renewal(&self, duration: Duration) {
        self.state
            .lock()
            .expect("state")
            .delay_next_preparation_renewal = Some(duration);
    }

    fn delay_next_activation_renewal(&self, duration: Duration) {
        self.state
            .lock()
            .expect("state")
            .delay_next_activation_renewal = Some(duration);
    }

    fn delay_next_materialization_renewal(&self, duration: Duration) {
        self.state
            .lock()
            .expect("state")
            .delay_next_materialization_renewal = Some(duration);
    }

    fn delay_next_orchestration_quarantine(&self, duration: Duration) {
        self.state
            .lock()
            .expect("state")
            .delay_next_orchestration_quarantine = Some(duration);
    }

    fn reject_next_quarantine(&self) {
        self.state.lock().expect("state").reject_next_quarantine = true;
    }

    fn cancel_on_orchestration_quarantine(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_orchestration_quarantine = Some(shutdown);
    }

    fn cancel_on_materialization_quarantine(&self, shutdown: CancellationToken) {
        self.state
            .lock()
            .expect("state")
            .cancel_on_materialization_quarantine = Some(shutdown);
    }

    fn consume_count(&self) -> usize {
        self.state
            .lock()
            .expect("state")
            .events
            .iter()
            .filter(|event| **event == "consume:o")
            .count()
    }

    fn events(&self) -> Vec<&'static str> {
        self.state.lock().expect("state").events.clone()
    }

    fn quarantined_generations(&self) -> Vec<u64> {
        self.state
            .lock()
            .expect("state")
            .quarantined_generations
            .clone()
    }

    fn orchestration_selection_requests(&self) -> Vec<ClaimNextLogicalJobOrchestration> {
        self.state
            .lock()
            .expect("state")
            .orchestration_selection_requests
            .clone()
    }

    fn materialization_selection_requests(&self) -> Vec<ClaimNextLogicalInstanceMaterialization> {
        self.state
            .lock()
            .expect("state")
            .materialization_selection_requests
            .clone()
    }

    fn orchestration_consume_requests(&self) -> Vec<ConsumeSelectedLogicalJobOrchestration> {
        self.state
            .lock()
            .expect("state")
            .orchestration_consume_requests
            .clone()
    }

    fn materialization_consume_requests(
        &self,
    ) -> Vec<ConsumeSelectedLogicalInstanceMaterialization> {
        self.state
            .lock()
            .expect("state")
            .materialization_consume_requests
            .clone()
    }

    fn preparation_renewal_requests(&self) -> Vec<RenewLogicalActivationPreparation> {
        self.state
            .lock()
            .expect("state")
            .preparation_renewal_requests
            .clone()
    }

    fn activation_renewal_requests(&self) -> Vec<RenewLogicalJobActivation> {
        self.state
            .lock()
            .expect("state")
            .activation_renewal_requests
            .clone()
    }

    fn materialization_renewal_requests(&self) -> Vec<RenewLogicalInstanceMaterialization> {
        self.state
            .lock()
            .expect("state")
            .materialization_renewal_requests
            .clone()
    }

    fn orchestration_quarantine_requests(&self) -> Vec<QuarantineLogicalJobOrchestration> {
        self.state
            .lock()
            .expect("state")
            .orchestration_quarantine_requests
            .clone()
    }

    fn materialization_quarantine_requests(&self) -> Vec<QuarantineLogicalInstanceMaterialization> {
        self.state
            .lock()
            .expect("state")
            .materialization_quarantine_requests
            .clone()
    }

    fn max_orchestration_select_in_flight(&self) -> usize {
        self.state
            .lock()
            .expect("state")
            .max_orchestration_select_in_flight
    }
}

#[async_trait]
impl LogicalWorkSelectionRepository for FakeRepository {
    async fn claim_next_logical_job_orchestration(
        &self,
        request: ClaimNextLogicalJobOrchestration,
    ) -> Result<LogicalJobOrchestrationSelectionOutcome, LogicalWorkSelectionStoreError> {
        let (outcome, cancellation, success_cancellation, delay, ambiguous, tracked) = {
            let mut state = self.state.lock().expect("state");
            state.events.push("select:o");
            state.orchestration_selection_requests.push(request.clone());
            let tracked = state.track_orchestration_select_concurrency;
            if tracked {
                state.orchestration_select_in_flight += 1;
                state.max_orchestration_select_in_flight = state
                    .max_orchestration_select_in_flight
                    .max(state.orchestration_select_in_flight);
            }
            if let Some((submitted, outcome)) = state.orchestration_selection_replay.take() {
                if submitted == request {
                    if state
                        .take_replay_operation_failure(FakeRepositoryOperation::OrchestrationSelect)
                    {
                        state.orchestration_selection_replay = Some((submitted, outcome));
                        if tracked {
                            state.orchestration_select_in_flight -= 1;
                        }
                        return Err(synthetic_selection_outage());
                    }
                    if tracked {
                        state.orchestration_select_in_flight -= 1;
                    }
                    return Ok(outcome);
                }
                state.orchestration_selection_replay = Some((submitted, outcome));
                if tracked {
                    state.orchestration_select_in_flight -= 1;
                }
                return Err(LogicalWorkSelectionStoreError::SelectionConflict);
            }
            let outcome = state
                .orchestration
                .pop_front()
                .unwrap_or(LogicalJobOrchestrationSelectionOutcome::Idle);
            let cancellation = state.cancel_on_orchestration_select.take();
            let success_cancellation = state.cancel_after_orchestration_select_success.take();
            let delay = state.delay_next_orchestration_select.take();
            let ambiguous = state.fail_next_orchestration_selection;
            state.fail_next_orchestration_selection = false;
            if cancellation.is_some() || delay.is_some() || ambiguous {
                state.orchestration_selection_replay = Some((request.clone(), outcome.clone()));
            }
            (
                outcome,
                cancellation,
                success_cancellation,
                delay,
                ambiguous,
                tracked,
            )
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if tracked {
            self.state
                .lock()
                .expect("state")
                .orchestration_select_in_flight -= 1;
        }
        if ambiguous {
            return Err(synthetic_selection_outage());
        }
        self.state
            .lock()
            .expect("state")
            .orchestration_selection_replay
            .take();
        if let Some(shutdown) = success_cancellation {
            shutdown.cancel();
        }
        Ok(outcome)
    }

    async fn claim_next_logical_instance_materialization(
        &self,
        request: ClaimNextLogicalInstanceMaterialization,
    ) -> Result<LogicalInstanceMaterializationSelectionOutcome, LogicalWorkSelectionStoreError>
    {
        let (outcome, cancellation, success_cancellation, ambiguous) = {
            let mut state = self.state.lock().expect("state");
            state.events.push("select:m");
            state
                .materialization_selection_requests
                .push(request.clone());
            if let Some((submitted, outcome)) = state.materialization_selection_replay.take() {
                if submitted == request {
                    if state.take_replay_operation_failure(
                        FakeRepositoryOperation::MaterializationSelect,
                    ) {
                        state.materialization_selection_replay = Some((submitted, outcome));
                        return Err(synthetic_selection_outage());
                    }
                    return Ok(outcome);
                }
                state.materialization_selection_replay = Some((submitted, outcome));
                return Err(LogicalWorkSelectionStoreError::SelectionConflict);
            }
            let outcome = state
                .materialization
                .pop_front()
                .unwrap_or(LogicalInstanceMaterializationSelectionOutcome::Idle);
            let cancellation = state.cancel_on_materialization_select.take();
            let success_cancellation = state.cancel_after_materialization_select_success.take();
            let ambiguous = state.fail_next_materialization_selection;
            state.fail_next_materialization_selection = false;
            if cancellation.is_some() || ambiguous {
                state.materialization_selection_replay = Some((request, outcome.clone()));
            }
            (outcome, cancellation, success_cancellation, ambiguous)
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        if ambiguous {
            return Err(synthetic_selection_outage());
        }
        self.state
            .lock()
            .expect("state")
            .materialization_selection_replay
            .take();
        if let Some(shutdown) = success_cancellation {
            shutdown.cancel();
        }
        Ok(outcome)
    }

    async fn consume_selected_logical_job_orchestration(
        &self,
        request: ConsumeSelectedLogicalJobOrchestration,
    ) -> Result<ConsumedSelectedLogicalJobOrchestration, LogicalWorkSelectionStoreError> {
        let (consumed, cancellation, delay, ambiguous) = {
            let mut state = self.state.lock().expect("state");
            state.events.push("consume:o");
            state.orchestration_consume_requests.push(request.clone());
            if let Some((submitted, consumed)) = state.orchestration_consume_replay.take() {
                if submitted == request {
                    if state.take_replay_operation_failure(
                        FakeRepositoryOperation::OrchestrationConsume,
                    ) {
                        state.orchestration_consume_replay = Some((submitted, consumed));
                        return Err(synthetic_selection_outage());
                    }
                    return Ok(consumed);
                }
                state.orchestration_consume_replay = Some((submitted, consumed));
                return Err(LogicalWorkSelectionStoreError::SelectionConflict);
            }
            let consumed = state
                .orchestration_consumes
                .pop_front()
                .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?;
            assert_eq!(consumed.selected(), request.selected());
            let cancellation = state.cancel_on_orchestration_consume.take();
            let delay = state.delay_next_orchestration_consume.take();
            let ambiguous = state.fail_next_orchestration_consume;
            state.fail_next_orchestration_consume = false;
            if cancellation.is_some() || delay.is_some() || ambiguous {
                state.orchestration_consume_replay = Some((request.clone(), consumed.clone()));
            }
            (consumed, cancellation, delay, ambiguous)
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if ambiguous {
            return Err(synthetic_selection_outage());
        }
        self.state
            .lock()
            .expect("state")
            .orchestration_consume_replay
            .take();
        Ok(consumed)
    }

    async fn consume_selected_logical_instance_materialization(
        &self,
        request: ConsumeSelectedLogicalInstanceMaterialization,
    ) -> Result<ConsumedSelectedLogicalInstanceMaterialization, LogicalWorkSelectionStoreError>
    {
        let (consumed, cancellation, ambiguous) = {
            let mut state = self.state.lock().expect("state");
            state.events.push("consume:m");
            state.materialization_consume_requests.push(request.clone());
            if let Some((submitted, consumed)) = state.materialization_consume_replay.take() {
                if submitted == request {
                    if state.take_replay_operation_failure(
                        FakeRepositoryOperation::MaterializationConsume,
                    ) {
                        state.materialization_consume_replay = Some((submitted, consumed));
                        return Err(synthetic_selection_outage());
                    }
                    return Ok(consumed);
                }
                state.materialization_consume_replay = Some((submitted, consumed));
                return Err(LogicalWorkSelectionStoreError::SelectionConflict);
            }
            let consumed = state
                .materialization_consumes
                .pop_front()
                .ok_or(LogicalWorkSelectionStoreError::SelectionExpired)?;
            assert_eq!(consumed.selected(), request.selected());
            let cancellation = state.cancel_on_materialization_consume.take();
            let ambiguous = state.fail_next_materialization_consume;
            state.fail_next_materialization_consume = false;
            if cancellation.is_some() || ambiguous {
                state.materialization_consume_replay = Some((request, consumed.clone()));
            }
            (consumed, cancellation, ambiguous)
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        if ambiguous {
            return Err(synthetic_selection_outage());
        }
        self.state
            .lock()
            .expect("state")
            .materialization_consume_replay
            .take();
        Ok(consumed)
    }

    async fn quarantine_logical_job_orchestration(
        &self,
        request: QuarantineLogicalJobOrchestration,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
        let generation = match request.consumed().authority() {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(authority) => {
                authority.claim().generation().get()
            }
            ConsumedLogicalJobOrchestrationAuthority::Activation(authority) => {
                authority.claim().generation().get()
            }
        };
        let (outcome, cancellation, delay) = {
            let mut state = self.state.lock().expect("state");
            state.events.push("quarantine:o");
            state
                .orchestration_quarantine_requests
                .push(request.clone());
            state.quarantined_generations.push(generation);
            if let Some((submitted, outcome)) = state.orchestration_quarantine_replay.take() {
                if submitted == request {
                    if state.take_replay_operation_failure(
                        FakeRepositoryOperation::OrchestrationQuarantine,
                    ) {
                        state.orchestration_quarantine_replay = Some((submitted, outcome));
                        return Err(synthetic_selection_outage());
                    }
                    return Ok(outcome);
                }
                state.orchestration_quarantine_replay = Some((submitted, outcome));
                return Err(LogicalWorkSelectionStoreError::SelectionConflict);
            }
            let outcome = if state.reject_next_quarantine {
                LogicalWorkQuarantineOutcome::FenceRejected
            } else {
                LogicalWorkQuarantineOutcome::Quarantined
            };
            state.reject_next_quarantine = false;
            let cancellation = state.cancel_on_orchestration_quarantine.take();
            let delay = state.delay_next_orchestration_quarantine.take();
            if cancellation.is_some() || delay.is_some() {
                state.orchestration_quarantine_replay = Some((request.clone(), outcome));
            }
            (outcome, cancellation, delay)
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        self.state
            .lock()
            .expect("state")
            .orchestration_quarantine_replay
            .take();
        Ok(outcome)
    }

    async fn quarantine_logical_instance_materialization(
        &self,
        request: QuarantineLogicalInstanceMaterialization,
    ) -> Result<LogicalWorkQuarantineOutcome, LogicalWorkSelectionStoreError> {
        let cancellation = {
            let mut state = self.state.lock().expect("state");
            state.events.push("quarantine:m");
            state
                .materialization_quarantine_requests
                .push(request.clone());
            state
                .quarantined_generations
                .push(request.consumed().authority().claim().generation().get());
            if let Some((submitted, outcome)) = state.materialization_quarantine_replay.take() {
                if submitted == request {
                    if state.take_replay_operation_failure(
                        FakeRepositoryOperation::MaterializationQuarantine,
                    ) {
                        state.materialization_quarantine_replay = Some((submitted, outcome));
                        return Err(synthetic_selection_outage());
                    }
                    return Ok(outcome);
                }
                state.materialization_quarantine_replay = Some((submitted, outcome));
                return Err(LogicalWorkSelectionStoreError::SelectionConflict);
            }
            let cancellation = state.cancel_on_materialization_quarantine.take();
            if cancellation.is_some() {
                state.materialization_quarantine_replay =
                    Some((request, LogicalWorkQuarantineOutcome::Quarantined));
            }
            cancellation
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        self.state
            .lock()
            .expect("state")
            .materialization_quarantine_replay
            .take();
        Ok(LogicalWorkQuarantineOutcome::Quarantined)
    }
}

fn synthetic_selection_outage() -> LogicalWorkSelectionStoreError {
    LogicalWorkSelectionStoreError::Store(StoreError::operation(std::io::Error::other(
        "synthetic outage",
    )))
}

fn synthetic_preparation_outage() -> LogicalActivationPreparationStoreError {
    LogicalActivationPreparationStoreError::Store(StoreError::operation(std::io::Error::other(
        "synthetic renewal outage",
    )))
}

fn synthetic_activation_outage() -> LogicalActivationStoreError {
    LogicalActivationStoreError::Store(StoreError::operation(std::io::Error::other(
        "synthetic renewal outage",
    )))
}

fn synthetic_materialization_outage() -> LogicalMaterializationStoreError {
    LogicalMaterializationStoreError::Store(StoreError::operation(std::io::Error::other(
        "synthetic renewal outage",
    )))
}

#[async_trait]
impl LogicalActivationPreparationStore for FakeRepository {
    async fn renew_logical_activation_preparation(
        &self,
        request: RenewLogicalActivationPreparation,
    ) -> Result<RenewedLogicalActivationPreparation, LogicalActivationPreparationStoreError> {
        let (response, cancellation, delay) = {
            let mut state = self.state.lock().expect("state");
            state.events.push(match request.claim().generation().get() {
                1 => "renew:p:1",
                _ => "renew:p:n",
            });
            state.preparation_renewal_requests.push(request.clone());
            if let Some((submitted, response)) = state.preparation_renewal_replay.take() {
                if submitted == request {
                    if state
                        .take_replay_operation_failure(FakeRepositoryOperation::PreparationRenew)
                    {
                        state.preparation_renewal_replay = Some((submitted, response));
                        return Err(synthetic_preparation_outage());
                    }
                    return Ok(response);
                }
                state.preparation_renewal_replay = Some((submitted, response));
                return Err(LogicalActivationPreparationStoreError::ClaimRejected);
            }
            if state.malformed_next_preparation_renewal {
                state.malformed_next_preparation_renewal = false;
                return Err(LogicalActivationPreparationStoreError::ClaimRejected);
            }
            if state.ambiguous_next_preparation_renewal {
                state.ambiguous_next_preparation_renewal = false;
                return Err(synthetic_preparation_outage());
            }
            let successor_generation =
                LogicalActivationPreparationGeneration::new(request.claim().generation().get() + 1)
                    .expect("replacement generation");
            let successor_claimed_at = UnixMillis::new(request.claim().claimed_at().get() + 1);
            let successor_expires_at =
                UnixMillis::new(successor_claimed_at.get() + request.duration_ms());
            let response = RenewedLogicalActivationPreparation::new(
                request.clone(),
                successor_generation,
                successor_claimed_at,
                successor_expires_at,
                successor_claimed_at,
            )
            .map_err(|_| LogicalActivationPreparationStoreError::ClaimRejected)?;
            let cancellation = state.cancel_on_preparation_renewal.take();
            let delay = state.delay_next_preparation_renewal.take();
            if cancellation.is_some() || delay.is_some() {
                state.preparation_renewal_replay = Some((request, response.clone()));
            }
            (response, cancellation, delay)
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        self.state
            .lock()
            .expect("state")
            .preparation_renewal_replay
            .take();
        Ok(response)
    }

    async fn bind_logical_activation_preparation(
        &self,
        _request: BindLogicalActivationPreparation,
    ) -> Result<
        automata_ci_store::LogicalActivationPreparationReceipt,
        LogicalActivationPreparationStoreError,
    > {
        Err(LogicalActivationPreparationStoreError::ClaimRejected)
    }
}

#[async_trait]
impl LogicalActivationRepository for FakeRepository {
    async fn renew_logical_job_activation(
        &self,
        request: RenewLogicalJobActivation,
    ) -> Result<RenewedLogicalJobActivation, LogicalActivationStoreError> {
        let (response, cancellation, delay) = {
            let mut state = self.state.lock().expect("state");
            state.events.push(match request.claim().generation().get() {
                1 => "renew:a:1",
                _ => "renew:a:n",
            });
            state.activation_renewal_requests.push(request.clone());
            if let Some((submitted, response)) = state.activation_renewal_replay.take() {
                if submitted == request {
                    if state.take_replay_operation_failure(FakeRepositoryOperation::ActivationRenew)
                    {
                        state.activation_renewal_replay = Some((submitted, response));
                        return Err(synthetic_activation_outage());
                    }
                    return Ok(response);
                }
                state.activation_renewal_replay = Some((submitted, response));
                return Err(LogicalActivationStoreError::ClaimRejected);
            }
            let successor_generation =
                LogicalActivationGeneration::new(request.claim().generation().get() + 1)
                    .expect("replacement generation");
            let successor_claimed_at = UnixMillis::new(request.claim().claimed_at().get() + 1);
            let successor_expires_at =
                UnixMillis::new(successor_claimed_at.get() + request.duration_ms());
            let response = RenewedLogicalJobActivation::new(
                request.clone(),
                successor_generation,
                successor_claimed_at,
                successor_expires_at,
                successor_claimed_at,
            )
            .map_err(|_| LogicalActivationStoreError::ClaimRejected)?;
            let cancellation = state.cancel_on_activation_renewal.take();
            let delay = state.delay_next_activation_renewal.take();
            if cancellation.is_some() || delay.is_some() {
                state.activation_renewal_replay = Some((request, response.clone()));
            }
            (response, cancellation, delay)
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        self.state
            .lock()
            .expect("state")
            .activation_renewal_replay
            .take();
        Ok(response)
    }

    async fn publish_logical_job_activation(
        &self,
        _request: PublishLogicalJobActivation,
    ) -> Result<automata_ci_store::LogicalActivationPublicationReceipt, LogicalActivationStoreError>
    {
        Err(LogicalActivationStoreError::ClaimRejected)
    }
}

#[async_trait]
impl LogicalMaterializationRepository for FakeRepository {
    async fn renew_logical_instance_materialization(
        &self,
        request: RenewLogicalInstanceMaterialization,
    ) -> Result<RenewedLogicalInstanceMaterialization, LogicalMaterializationStoreError> {
        let (response, cancellation, delay) = {
            let mut state = self.state.lock().expect("state");
            state.events.push(match request.claim().generation().get() {
                1 => "renew:m:1",
                _ => "renew:m:n",
            });
            state.materialization_renewal_requests.push(request.clone());
            if let Some((submitted, response)) = state.materialization_renewal_replay.take() {
                if submitted == request {
                    if state.take_replay_operation_failure(
                        FakeRepositoryOperation::MaterializationRenew,
                    ) {
                        state.materialization_renewal_replay = Some((submitted, response));
                        return Err(synthetic_materialization_outage());
                    }
                    return Ok(response);
                }
                state.materialization_renewal_replay = Some((submitted, response));
                return Err(LogicalMaterializationStoreError::ClaimRejected);
            }
            let successor_generation =
                LogicalMaterializationGeneration::new(request.claim().generation().get() + 1)
                    .expect("replacement generation");
            let successor_claimed_at = UnixMillis::new(request.claim().claimed_at().get() + 1);
            let successor_expires_at =
                UnixMillis::new(successor_claimed_at.get() + request.duration_ms());
            let response = RenewedLogicalInstanceMaterialization::new(
                request.clone(),
                successor_generation,
                successor_claimed_at,
                successor_expires_at,
                successor_claimed_at,
            )
            .map_err(|_| LogicalMaterializationStoreError::ClaimRejected)?;
            let cancellation = state.cancel_on_materialization_renewal.take();
            let delay = state.delay_next_materialization_renewal.take();
            if cancellation.is_some() || delay.is_some() {
                state.materialization_renewal_replay = Some((request, response.clone()));
            }
            (response, cancellation, delay)
        };
        if let Some(shutdown) = cancellation {
            shutdown.cancel();
            tokio::task::yield_now().await;
        }
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        self.state
            .lock()
            .expect("state")
            .materialization_renewal_replay
            .take();
        Ok(response)
    }

    async fn commit_logical_instance_materialization(
        &self,
        _request: CommitLogicalInstanceMaterialization,
    ) -> Result<automata_ci_store::LogicalMaterializationReceipt, LogicalMaterializationStoreError>
    {
        Err(LogicalMaterializationStoreError::ClaimRejected)
    }
}

#[derive(Clone, Copy, Debug)]
enum ExecutorMode {
    Complete,
    BlockOnceAfterIo,
    Renew,
    RenewOnce,
    Evidence,
    RenewThenEvidence,
    CrossDeadline,
    EvidenceNearDeadline,
    UnboundFinalReadyOnce,
    UnboundFinalOperationOnce,
}

#[derive(Debug)]
struct FakeExecutor {
    mode: ExecutorMode,
    state: Mutex<FakeExecutorState>,
}

#[derive(Debug, Default)]
struct FakeExecutorState {
    phases: Vec<AutonomousWorkflowPhase>,
    generations: Vec<u64>,
    renewals: Vec<AutonomousWorkflowRenewalOutcome>,
    profiles: Vec<JobAuthorityProfile>,
    debug_types: Vec<String>,
    io_count: usize,
    blocked_once: bool,
    renewed_once: bool,
    final_marker_returned: bool,
}

impl FakeExecutor {
    fn new(mode: ExecutorMode) -> Self {
        Self {
            mode,
            state: Mutex::new(FakeExecutorState::default()),
        }
    }

    fn io_count(&self) -> usize {
        self.state.lock().expect("state").io_count
    }

    fn phases(&self) -> Vec<AutonomousWorkflowPhase> {
        self.state.lock().expect("state").phases.clone()
    }

    fn generations(&self) -> Vec<u64> {
        self.state.lock().expect("state").generations.clone()
    }

    fn renewals(&self) -> Vec<AutonomousWorkflowRenewalOutcome> {
        self.state.lock().expect("state").renewals.clone()
    }

    fn profiles(&self) -> Vec<JobAuthorityProfile> {
        self.state.lock().expect("state").profiles.clone()
    }

    fn debug_types(&self) -> Vec<String> {
        self.state.lock().expect("state").debug_types.clone()
    }

    fn record_debug(&self, lease: &dyn std::fmt::Debug, deadline: &AutonomousWorkflowDeadline) {
        let mut state = self.state.lock().expect("state");
        state.debug_types.push(format!("{lease:?}"));
        state.debug_types.push(format!("{deadline:?}"));
    }

    fn record_io(&self, phase: AutonomousWorkflowPhase) {
        let mut state = self.state.lock().expect("state");
        state.io_count += 1;
        state.phases.push(phase);
    }

    fn take_one_shot_renewal(&self) -> bool {
        if !matches!(self.mode, ExecutorMode::RenewOnce) {
            return false;
        }
        let mut state = self.state.lock().expect("state");
        let should_renew = !state.renewed_once;
        state.renewed_once = true;
        should_renew
    }

    fn take_unbound_final_marker(&self) -> Option<AutonomousWorkflowExecutionOutcome> {
        let outcome = match self.mode {
            ExecutorMode::UnboundFinalReadyOnce => {
                AutonomousWorkflowExecutionOutcome::FinalRequestReady
            }
            ExecutorMode::UnboundFinalOperationOnce => {
                AutonomousWorkflowExecutionOutcome::FinalRequestOperation
            }
            _ => return None,
        };
        let mut state = self.state.lock().expect("state");
        if state.final_marker_returned {
            None
        } else {
            state.final_marker_returned = true;
            Some(outcome)
        }
    }
}

impl AutonomousWorkflowPhaseExecutor for FakeExecutor {
    fn execute_preparation<'a>(
        &'a self,
        lease: &'a mut AutonomousPreparationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move {
            self.record_debug(lease, &deadline);
            lease.before_io(&shutdown)?;
            self.record_io(AutonomousWorkflowPhase::Preparation);
            self.state
                .lock()
                .expect("state")
                .profiles
                .push(lease.authority().descriptor().authority_profile());
            if let Some(outcome) = self.take_unbound_final_marker() {
                return Ok(outcome);
            }
            let block_once = if matches!(self.mode, ExecutorMode::BlockOnceAfterIo) {
                let mut state = self.state.lock().expect("state");
                let block = !state.blocked_once;
                state.blocked_once = true;
                block
            } else {
                false
            };
            if block_once {
                tokio::time::sleep(Duration::from_mins(1)).await;
            }
            if matches!(self.mode, ExecutorMode::CrossDeadline) {
                tokio::time::sleep(Duration::from_millis(800)).await;
                lease.before_io(&shutdown)?;
                self.state.lock().expect("state").io_count += 1;
                return Ok(AutonomousWorkflowExecutionOutcome::Completed);
            }
            if matches!(self.mode, ExecutorMode::EvidenceNearDeadline) {
                tokio::time::sleep(Duration::from_millis(700)).await;
                lease.before_io(&shutdown)?;
                return Ok(AutonomousWorkflowExecutionOutcome::EvidenceFailure(
                    LogicalWorkQuarantineKind::PayloadEvidence,
                ));
            }
            if matches!(
                self.mode,
                ExecutorMode::Renew | ExecutorMode::RenewThenEvidence
            ) || self.take_one_shot_renewal()
            {
                let renewal = lease.renew(&shutdown).await?;
                self.state.lock().expect("state").renewals.push(renewal);
                lease.before_io(&shutdown)?;
                self.state
                    .lock()
                    .expect("state")
                    .generations
                    .push(lease.authority().claim().generation().get());
                self.state.lock().expect("state").io_count += 1;
            }
            if matches!(
                self.mode,
                ExecutorMode::Evidence | ExecutorMode::RenewThenEvidence
            ) {
                Ok(AutonomousWorkflowExecutionOutcome::EvidenceFailure(
                    LogicalWorkQuarantineKind::PayloadEvidence,
                ))
            } else {
                Ok(AutonomousWorkflowExecutionOutcome::Completed)
            }
        })
    }

    fn execute_activation<'a>(
        &'a self,
        lease: &'a mut AutonomousActivationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move {
            self.record_debug(lease, &deadline);
            lease.before_io(&shutdown)?;
            self.record_io(AutonomousWorkflowPhase::Activation);
            if matches!(self.mode, ExecutorMode::Renew) || self.take_one_shot_renewal() {
                let renewal = lease.renew(&shutdown).await?;
                let mut state = self.state.lock().expect("state");
                state.renewals.push(renewal);
                state
                    .generations
                    .push(lease.authority().claim().generation().get());
                state.io_count += 1;
            }
            Ok(AutonomousWorkflowExecutionOutcome::Completed)
        })
    }

    fn execute_materialization<'a>(
        &'a self,
        lease: &'a mut AutonomousMaterializationLease,
        shutdown: CancellationToken,
        deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move {
            self.record_debug(lease, &deadline);
            lease.before_io(&shutdown)?;
            self.record_io(AutonomousWorkflowPhase::Materialization);
            if matches!(self.mode, ExecutorMode::Renew) || self.take_one_shot_renewal() {
                let renewal = lease.renew(&shutdown).await?;
                let mut state = self.state.lock().expect("state");
                state.renewals.push(renewal);
                state
                    .generations
                    .push(lease.authority().claim().generation().get());
                state.io_count += 1;
            }
            if matches!(self.mode, ExecutorMode::Evidence) {
                Ok(AutonomousWorkflowExecutionOutcome::EvidenceFailure(
                    LogicalWorkQuarantineKind::PayloadEvidence,
                ))
            } else {
                Ok(AutonomousWorkflowExecutionOutcome::Completed)
            }
        })
    }
}
