//! Bounded pre-scheduling advancement for protected job environments.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_control::lease::{RunnableAttemptGate, RunnableAttemptGateDisposition};
use automata_ci_core::{AttemptId, UnixMillis};
use automata_ci_store::{
    JobEnvironmentGatePhase, JobEnvironmentGateState, PrepareJobEnvironment,
    ProtectedEnvironmentRepository, ProtectedEnvironmentStoreError, StoreError, TenantScope,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const APPROVAL_REQUEST_ID_DOMAIN: &[u8] =
    b"automata/server/protected-environment-approval-request:v1\0";
const APPROVAL_LIFETIME_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;

/// Advances value-free environment selection before an attempt reaches the scheduler.
pub(crate) struct ProtectedEnvironmentLeaseGate {
    repository: Arc<dyn ProtectedEnvironmentRepository>,
    tenant: TenantScope,
}

impl ProtectedEnvironmentLeaseGate {
    #[must_use]
    pub(crate) const fn new(
        repository: Arc<dyn ProtectedEnvironmentRepository>,
        tenant: TenantScope,
    ) -> Self {
        Self { repository, tenant }
    }

    async fn resolve(
        &self,
        attempt_id: AttemptId,
    ) -> Result<RunnableAttemptGateDisposition, StoreError> {
        let state = self
            .repository
            .resolve_job_credentials(&self.tenant, attempt_id)
            .await;
        if state
            .as_ref()
            .is_ok_and(|state| terminal_gate_state(*state))
        {
            return self.conclude_terminal(attempt_id).await;
        }
        gate_state_disposition(state)
    }

    async fn conclude_terminal(
        &self,
        attempt_id: AttemptId,
    ) -> Result<RunnableAttemptGateDisposition, StoreError> {
        match self
            .repository
            .conclude_terminal_job_environment(&self.tenant, attempt_id)
            .await
        {
            Ok(()) => Ok(RunnableAttemptGateDisposition::Ineligible),
            Err(error) => protected_error_disposition(error),
        }
    }
}

impl fmt::Debug for ProtectedEnvironmentLeaseGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedEnvironmentLeaseGate")
            .field("repository", &"ProtectedEnvironmentRepository(..)")
            .field("tenant", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl RunnableAttemptGate for ProtectedEnvironmentLeaseGate {
    async fn evaluate(
        &self,
        attempt_id: AttemptId,
        observed_at: UnixMillis,
    ) -> Result<RunnableAttemptGateDisposition, StoreError> {
        let snapshot = match self
            .repository
            .inspect_job_environment_gate(&self.tenant, attempt_id)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => return protected_error_disposition(error),
        };

        // Terminal gates must progress even when the job has variable
        // references whose values cannot otherwise be resolved yet.
        if snapshot.phase() == JobEnvironmentGatePhase::Terminal {
            return self.conclude_terminal(attempt_id).await;
        }

        // Variable versions are value-free selectors, but no ephemeral value
        // custody path exists yet. Keeping such attempts queued prevents a
        // durable selector from being mistaken for an executable value.
        if snapshot.variable_reference_count() != 0 {
            return Ok(RunnableAttemptGateDisposition::Ineligible);
        }

        match snapshot.phase() {
            JobEnvironmentGatePhase::Ready => Ok(RunnableAttemptGateDisposition::Ready),
            JobEnvironmentGatePhase::Waiting => Ok(RunnableAttemptGateDisposition::Ineligible),
            JobEnvironmentGatePhase::Terminal => unreachable!("terminal gate handled above"),
            JobEnvironmentGatePhase::Resolving => self.resolve(attempt_id).await,
            JobEnvironmentGatePhase::SelectionPending => {
                let Some(activation) = snapshot.activation() else {
                    return Ok(RunnableAttemptGateDisposition::Ineligible);
                };
                if observed_at < snapshot.created_at() {
                    return Ok(RunnableAttemptGateDisposition::Ineligible);
                }
                let Some(expires_at_millis) = snapshot
                    .created_at()
                    .get()
                    .checked_add(APPROVAL_LIFETIME_MILLIS)
                else {
                    return Err(StoreError::corrupt_data(
                        "protected environment approval lifetime overflows",
                    ));
                };
                let expires_at = UnixMillis::new(expires_at_millis);
                if expires_at <= observed_at {
                    return Ok(RunnableAttemptGateDisposition::Ineligible);
                }
                let request = PrepareJobEnvironment::new(
                    self.tenant.clone(),
                    attempt_id,
                    activation.environment().cloned(),
                    snapshot.runtime_context_digest(),
                    activation.event_trust(),
                    activation.source_kind(),
                    activation.reusable_secret_permission(),
                    approval_request_id(attempt_id),
                    observed_at,
                    expires_at,
                )
                .map_err(|_| {
                    StoreError::corrupt_data("protected environment gate request is invalid")
                })?;
                match self.repository.prepare_job_environment(request).await {
                    Ok(JobEnvironmentGateState::Resolving) => self.resolve(attempt_id).await,
                    Ok(state) if terminal_gate_state(state) => {
                        self.conclude_terminal(attempt_id).await
                    }
                    state => gate_state_disposition(state),
                }
            }
        }
    }
}

const fn terminal_gate_state(state: JobEnvironmentGateState) -> bool {
    matches!(
        state,
        JobEnvironmentGateState::Rejected
            | JobEnvironmentGateState::Expired
            | JobEnvironmentGateState::Cancelled
    )
}

fn gate_state_disposition(
    state: Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError>,
) -> Result<RunnableAttemptGateDisposition, StoreError> {
    match state {
        Ok(JobEnvironmentGateState::Ready) => Ok(RunnableAttemptGateDisposition::Ready),
        Ok(
            JobEnvironmentGateState::Waiting
            | JobEnvironmentGateState::Resolving
            | JobEnvironmentGateState::Rejected
            | JobEnvironmentGateState::Expired
            | JobEnvironmentGateState::Cancelled,
        ) => Ok(RunnableAttemptGateDisposition::Ineligible),
        Err(error) => protected_error_disposition(error),
    }
}

fn protected_error_disposition(
    error: ProtectedEnvironmentStoreError,
) -> Result<RunnableAttemptGateDisposition, StoreError> {
    match error {
        ProtectedEnvironmentStoreError::Operation(error) => Err(error),
        ProtectedEnvironmentStoreError::CorruptData => Err(StoreError::corrupt_data(
            "protected environment data is corrupt",
        )),
        ProtectedEnvironmentStoreError::NotFound
        | ProtectedEnvironmentStoreError::AuthorityRejected
        | ProtectedEnvironmentStoreError::Conflict => {
            Ok(RunnableAttemptGateDisposition::Ineligible)
        }
    }
}

fn approval_request_id(attempt_id: AttemptId) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(APPROVAL_REQUEST_ID_DOMAIN);
    hasher.update(attempt_id.as_uuid().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use automata_ci_core::Sha256Digest;
    use automata_ci_store::{
        BindLeasedJobSecrets, DeploymentEnvironmentName, InspectLeasedJobSecretBindings,
        IssueLeasedJobSecretGrants, IssuedLeasedJobSecretBinding, JobEnvironmentActivationEvidence,
        JobEnvironmentGateSnapshot, JobEventTrust, JobSourceKind, ReusableSecretPermission,
        ReviewJobEnvironment,
    };

    use super::*;

    #[derive(Debug)]
    struct FakeRepository {
        snapshot: JobEnvironmentGateSnapshot,
        prepare_state: Mutex<JobEnvironmentGateState>,
        resolve_state: Mutex<JobEnvironmentGateState>,
        prepare_calls: AtomicUsize,
        resolve_calls: AtomicUsize,
        terminal_calls: AtomicUsize,
    }

    impl FakeRepository {
        fn new(snapshot: JobEnvironmentGateSnapshot) -> Self {
            Self {
                snapshot,
                prepare_state: Mutex::new(JobEnvironmentGateState::Resolving),
                resolve_state: Mutex::new(JobEnvironmentGateState::Ready),
                prepare_calls: AtomicUsize::new(0),
                resolve_calls: AtomicUsize::new(0),
                terminal_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ProtectedEnvironmentRepository for FakeRepository {
        async fn inspect_job_environment_gate(
            &self,
            _tenant: &TenantScope,
            _attempt_id: AttemptId,
        ) -> Result<JobEnvironmentGateSnapshot, ProtectedEnvironmentStoreError> {
            Ok(self.snapshot.clone())
        }

        async fn prepare_job_environment(
            &self,
            _request: PrepareJobEnvironment,
        ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
            self.prepare_calls.fetch_add(1, Ordering::Relaxed);
            Ok(*self.prepare_state.lock().expect("prepare state"))
        }

        async fn review_job_environment(
            &self,
            _request: ReviewJobEnvironment,
        ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
            Err(ProtectedEnvironmentStoreError::AuthorityRejected)
        }

        async fn conclude_terminal_job_environment(
            &self,
            _tenant: &TenantScope,
            _attempt_id: AttemptId,
        ) -> Result<(), ProtectedEnvironmentStoreError> {
            self.terminal_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn resolve_job_credentials(
            &self,
            _tenant: &TenantScope,
            _attempt_id: AttemptId,
        ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentStoreError> {
            self.resolve_calls.fetch_add(1, Ordering::Relaxed);
            Ok(*self.resolve_state.lock().expect("resolve state"))
        }

        async fn bind_leased_job_secrets(
            &self,
            _request: BindLeasedJobSecrets,
        ) -> Result<(), ProtectedEnvironmentStoreError> {
            Ok(())
        }

        async fn issue_leased_job_secret_grants(
            &self,
            _request: IssueLeasedJobSecretGrants,
        ) -> Result<Vec<IssuedLeasedJobSecretBinding>, ProtectedEnvironmentStoreError> {
            Ok(Vec::new())
        }

        async fn inspect_leased_job_secret_bindings(
            &self,
            _request: InspectLeasedJobSecretBindings,
        ) -> Result<Vec<IssuedLeasedJobSecretBinding>, ProtectedEnvironmentStoreError> {
            Ok(Vec::new())
        }
    }

    fn tenant() -> TenantScope {
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant")
    }

    fn attempt() -> AttemptId {
        AttemptId::from_uuid(Uuid::from_u128(7))
    }

    fn activation() -> JobEnvironmentActivationEvidence {
        JobEnvironmentActivationEvidence::new(
            Some(DeploymentEnvironmentName::new("production").expect("environment")),
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        )
    }

    fn snapshot(
        phase: JobEnvironmentGatePhase,
        variable_reference_count: usize,
    ) -> JobEnvironmentGateSnapshot {
        JobEnvironmentGateSnapshot::new(
            phase,
            Some(activation()),
            Sha256Digest::from_bytes([3; 32]),
            UnixMillis::new(1_000),
            variable_reference_count,
        )
    }

    #[tokio::test]
    async fn ready_attempt_passes_without_mutation() {
        let repository = Arc::new(FakeRepository::new(snapshot(
            JobEnvironmentGatePhase::Ready,
            0,
        )));
        let gate = ProtectedEnvironmentLeaseGate::new(repository.clone(), tenant());

        assert_eq!(
            gate.evaluate(attempt(), UnixMillis::new(2_000))
                .await
                .expect("gate"),
            RunnableAttemptGateDisposition::Ready
        );
        assert_eq!(repository.prepare_calls.load(Ordering::Relaxed), 0);
        assert_eq!(repository.resolve_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn variable_reference_blocks_before_any_resolution() {
        let repository = Arc::new(FakeRepository::new(snapshot(
            JobEnvironmentGatePhase::SelectionPending,
            1,
        )));
        let gate = ProtectedEnvironmentLeaseGate::new(repository.clone(), tenant());

        assert_eq!(
            gate.evaluate(attempt(), UnixMillis::new(2_000))
                .await
                .expect("gate"),
            RunnableAttemptGateDisposition::Ineligible
        );
        assert_eq!(repository.prepare_calls.load(Ordering::Relaxed), 0);
        assert_eq!(repository.resolve_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn selection_and_resolution_complete_before_runnable() {
        let repository = Arc::new(FakeRepository::new(snapshot(
            JobEnvironmentGatePhase::SelectionPending,
            0,
        )));
        let gate = ProtectedEnvironmentLeaseGate::new(repository.clone(), tenant());

        assert_eq!(
            gate.evaluate(attempt(), UnixMillis::new(2_000))
                .await
                .expect("gate"),
            RunnableAttemptGateDisposition::Ready
        );
        assert_eq!(repository.prepare_calls.load(Ordering::Relaxed), 1);
        assert_eq!(repository.resolve_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn waiting_gate_stays_ineligible_until_the_store_proves_a_terminal_state() {
        let repository = Arc::new(FakeRepository::new(snapshot(
            JobEnvironmentGatePhase::Waiting,
            0,
        )));
        let gate = ProtectedEnvironmentLeaseGate::new(repository.clone(), tenant());
        assert_eq!(
            gate.evaluate(attempt(), UnixMillis::new(2_000))
                .await
                .expect("gate"),
            RunnableAttemptGateDisposition::Ineligible
        );
        assert_eq!(repository.prepare_calls.load(Ordering::Relaxed), 0);
        assert_eq!(repository.resolve_calls.load(Ordering::Relaxed), 0);
        assert_eq!(repository.terminal_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn terminal_gate_concludes_even_when_variable_resolution_is_blocked() {
        let repository = Arc::new(FakeRepository::new(snapshot(
            JobEnvironmentGatePhase::Terminal,
            1,
        )));
        let gate = ProtectedEnvironmentLeaseGate::new(repository.clone(), tenant());

        assert_eq!(
            gate.evaluate(attempt(), UnixMillis::new(2_000))
                .await
                .expect("gate"),
            RunnableAttemptGateDisposition::Ineligible
        );
        assert_eq!(repository.prepare_calls.load(Ordering::Relaxed), 0);
        assert_eq!(repository.resolve_calls.load(Ordering::Relaxed), 0);
        assert_eq!(repository.terminal_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn approval_identity_is_retry_stable_and_uuid_v8() {
        let first = approval_request_id(attempt());
        assert_eq!(first, approval_request_id(attempt()));
        assert_eq!(first.get_version_num(), 8);
        assert_ne!(
            first,
            approval_request_id(AttemptId::from_uuid(Uuid::from_u128(8)))
        );
    }
}
