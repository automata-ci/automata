//! Concrete GitHub phase execution under selection-owned authority.

use std::{fmt, sync::Arc};

use automata_ci_blob::ImmutableBlobStore;
use automata_ci_job_executor_actions::ActionPreparationPort;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    LogicalActivationPreparationStore, LogicalActivationRepository,
    LogicalMaterializationRepository,
};
use tokio_util::sync::CancellationToken;

use crate::{
    AdmissionClock, AutonomousActivationLease, AutonomousMaterializationLease,
    AutonomousPreparationLease, AutonomousWorkflowDeadline, AutonomousWorkflowExecutionFuture,
    AutonomousWorkflowPhaseExecutor,
    activation_preparation::StoreBackedLogicalActivationPreparationRepository,
    materialization::LogicalInstanceMaterializationService,
    orchestration::GithubLogicalJobOrchestrationService,
};

/// Production GitHub executor for the three selected pre-run workflow phases.
///
/// This adapter never acquires a phase claim. It delegates only to the
/// selected-authority entry points, whose worker-owned leases checkpoint every
/// external operation and reconcile renewal ambiguity through the originating
/// selection receipt.
#[derive(Clone)]
pub struct GithubAutonomousWorkflowPhaseExecutor {
    preparation: StoreBackedLogicalActivationPreparationRepository,
    activation: GithubLogicalJobOrchestrationService,
    materialization: LogicalInstanceMaterializationService,
}

impl fmt::Debug for GithubAutonomousWorkflowPhaseExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GithubAutonomousWorkflowPhaseExecutor")
    }
}

impl GithubAutonomousWorkflowPhaseExecutor {
    /// Composes all three phases with the default protocol resource budget.
    #[must_use]
    pub fn new(
        blobs: Arc<dyn ImmutableBlobStore>,
        preparations: Arc<dyn LogicalActivationPreparationStore>,
        activations: Arc<dyn LogicalActivationRepository>,
        materializations: Arc<dyn LogicalMaterializationRepository>,
        clock: Arc<dyn AdmissionClock>,
    ) -> Self {
        Self::with_limits(
            blobs,
            preparations,
            activations,
            materializations,
            clock,
            ProtocolLimits::default(),
        )
    }

    /// Composes all three phases with an explicit trusted protocol budget.
    #[must_use]
    pub fn with_limits(
        blobs: Arc<dyn ImmutableBlobStore>,
        preparations: Arc<dyn LogicalActivationPreparationStore>,
        activations: Arc<dyn LogicalActivationRepository>,
        materializations: Arc<dyn LogicalMaterializationRepository>,
        clock: Arc<dyn AdmissionClock>,
        limits: ProtocolLimits,
    ) -> Self {
        let preparation = StoreBackedLogicalActivationPreparationRepository::with_limits(
            preparations,
            Arc::clone(&blobs),
            Arc::clone(&clock),
            limits,
        );
        let activation = GithubLogicalJobOrchestrationService::with_limits(
            Arc::clone(&blobs),
            activations,
            Arc::clone(&clock),
            limits,
        );
        let materialization = LogicalInstanceMaterializationService::with_limits(
            blobs,
            materializations,
            clock,
            limits,
        );
        Self {
            preparation,
            activation,
            materialization,
        }
    }

    /// Composes all phases with repository-action metadata preparation at the
    /// activation boundary, before executable jobs can reach scheduling.
    #[must_use]
    pub fn with_limits_and_action_preparer(
        blobs: Arc<dyn ImmutableBlobStore>,
        preparations: Arc<dyn LogicalActivationPreparationStore>,
        activations: Arc<dyn LogicalActivationRepository>,
        materializations: Arc<dyn LogicalMaterializationRepository>,
        clock: Arc<dyn AdmissionClock>,
        limits: ProtocolLimits,
        actions: Arc<dyn ActionPreparationPort>,
    ) -> Self {
        let preparation = StoreBackedLogicalActivationPreparationRepository::with_limits(
            preparations,
            Arc::clone(&blobs),
            Arc::clone(&clock),
            limits,
        );
        let activation = GithubLogicalJobOrchestrationService::with_limits_and_action_preparer(
            Arc::clone(&blobs),
            activations,
            Arc::clone(&clock),
            limits,
            actions,
        );
        let materialization = LogicalInstanceMaterializationService::with_limits(
            blobs,
            materializations,
            clock,
            limits,
        );
        Self {
            preparation,
            activation,
            materialization,
        }
    }
}

impl AutonomousWorkflowPhaseExecutor for GithubAutonomousWorkflowPhaseExecutor {
    fn execute_preparation<'a>(
        &'a self,
        lease: &'a mut AutonomousPreparationLease,
        shutdown: CancellationToken,
        _deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move { self.preparation.prepare_selected(lease, &shutdown).await })
    }

    fn execute_activation<'a>(
        &'a self,
        lease: &'a mut AutonomousActivationLease,
        shutdown: CancellationToken,
        _deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move { self.activation.activate_selected(lease, &shutdown).await })
    }

    fn execute_materialization<'a>(
        &'a self,
        lease: &'a mut AutonomousMaterializationLease,
        shutdown: CancellationToken,
        _deadline: AutonomousWorkflowDeadline,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move {
            self.materialization
                .materialize_selected(lease, &shutdown)
                .await
        })
    }

    fn submit_preparation_final<'a>(
        &'a self,
        lease: &'a AutonomousPreparationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move { self.preparation.submit_ready_binding(lease).await })
    }

    fn submit_activation_final<'a>(
        &'a self,
        lease: &'a AutonomousActivationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move { self.activation.submit_ready_publication(lease).await })
    }

    fn submit_materialization_final<'a>(
        &'a self,
        lease: &'a AutonomousMaterializationLease,
    ) -> AutonomousWorkflowExecutionFuture<'a> {
        Box::pin(async move { self.materialization.submit_ready_commit(lease).await })
    }
}
