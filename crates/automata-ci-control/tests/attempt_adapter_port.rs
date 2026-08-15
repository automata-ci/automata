use std::{error::Error, fmt};

use async_trait::async_trait;
use automata_ci_control::{
    adapter_spi::{
        AcquireLease, AttemptSnapshot, ConcludeQueuedAttempt, InternalAttemptRepository,
        QueuedAttempt, TenantAttemptQuery, TransitionAttempt,
    },
    attempt::RenewLease,
};
use automata_ci_core::{AttemptId, AttemptNumber, JobId, JobLifecycle, Lease, UnixMillis};
use automata_ci_store::{AttemptStoreError, TenantScope};

#[derive(Debug)]
struct AlternativeBackendError(&'static str);

impl fmt::Display for AlternativeBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for AlternativeBackendError {}

#[derive(Debug)]
struct AlternativeAdapter {
    snapshot: AttemptSnapshot,
}

fn unavailable() -> AttemptStoreError {
    AttemptStoreError::operation(AlternativeBackendError("private backend detail"))
}

#[async_trait]
impl InternalAttemptRepository for AlternativeAdapter {
    async fn insert_queued(&self, _attempt: QueuedAttempt) -> Result<(), AttemptStoreError> {
        Err(unavailable())
    }

    async fn get_attempt(
        &self,
        _attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError> {
        Ok(self.snapshot)
    }

    async fn acquire_lease(&self, _request: AcquireLease) -> Result<Lease, AttemptStoreError> {
        Err(unavailable())
    }

    async fn conclude_queued(
        &self,
        _request: ConcludeQueuedAttempt,
    ) -> Result<(), AttemptStoreError> {
        Err(unavailable())
    }

    async fn renew_lease(&self, _request: RenewLease) -> Result<Lease, AttemptStoreError> {
        Err(unavailable())
    }

    async fn transition(&self, _request: TransitionAttempt) -> Result<(), AttemptStoreError> {
        Err(unavailable())
    }

    async fn requeue_expired(
        &self,
        _now: UnixMillis,
        _maximum_failures: u32,
        _limit: u32,
    ) -> Result<Vec<AttemptId>, AttemptStoreError> {
        Err(unavailable())
    }
}

#[async_trait]
impl TenantAttemptQuery for AlternativeAdapter {
    async fn get_attempt_for_tenant(
        &self,
        _tenant: &TenantScope,
        _attempt_id: AttemptId,
    ) -> Result<AttemptSnapshot, AttemptStoreError> {
        Ok(self.snapshot)
    }
}

#[tokio::test]
async fn alternative_adapter_implements_ports_with_only_neutral_types() {
    let attempt_id = AttemptId::new();
    let snapshot = AttemptSnapshot::builder(
        attempt_id,
        JobId::new(),
        AttemptNumber::new(1).expect("attempt number"),
        JobLifecycle::Queued,
        UnixMillis::new(10),
        UnixMillis::new(10),
    )
    .build()
    .expect("snapshot");
    let adapter = AlternativeAdapter { snapshot };

    assert_eq!(
        adapter
            .get_attempt(attempt_id)
            .await
            .expect("portable query"),
        snapshot
    );
    let tenant = TenantScope::from_authenticated_tenant_id("tenant-1").expect("tenant");
    assert_eq!(
        adapter
            .get_attempt_for_tenant(&tenant, attempt_id)
            .await
            .expect("tenant query"),
        snapshot
    );
}

#[test]
fn operation_errors_are_sanitized_but_retain_an_opaque_source() {
    let error = unavailable();
    assert_eq!(error.to_string(), "attempt repository operation failed");
    assert!(!error.to_string().contains("private backend detail"));

    let source = Error::source(&error).expect("opaque diagnostic source");
    assert_eq!(source.to_string(), "private backend detail");
}
