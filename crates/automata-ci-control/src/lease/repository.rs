use crate::lease::{
    BeginLeaseRequest, BegunLeaseRequest, CompleteLeaseRequest, LeaseRequestCompletion,
    LeaseRequestKey, NoWorkLeaseRequest, RunnableScanPage, RunnableScanRequest, TryClaimAttempt,
    TryClaimReceipt,
};
use async_trait::async_trait;
use automata_ci_protocol::LeaseAuthorityPollContributions;
use automata_ci_store::StoreError;

/// Bounded exact-response ledger for lease-request chains.
#[async_trait]
pub trait RunnerLeaseRequestRepository: Send + Sync {
    /// Admits a first request, exact retry, or exact completed-head successor.
    async fn begin_lease_request(
        &self,
        request: BeginLeaseRequest,
    ) -> Result<BegunLeaseRequest, StoreError>;

    /// Commits the exact response only if the request is still the slot head.
    async fn complete_lease_request(
        &self,
        request: CompleteLeaseRequest,
    ) -> Result<LeaseRequestCompletion, StoreError>;
}

/// Receipt-backed server-side claim port.
#[async_trait]
pub trait RunnerClaimRepository: Send + Sync {
    /// Looks up a terminal receipt before candidate selection. This is the
    /// mandatory first step for an at-least-once lease poll retry.
    async fn lookup_lease_request(
        &self,
        request: LeaseRequestKey,
        authority_contributions: &LeaseAuthorityPollContributions,
    ) -> Result<Option<TryClaimReceipt>, StoreError>;

    /// Claims one scheduler-selected candidate and records the answer in the
    /// same transaction. Same-session retries replay; digest changes conflict.
    async fn try_claim(&self, request: TryClaimAttempt) -> Result<TryClaimReceipt, StoreError>;

    /// Durably records that the first execution observed no schedulable work.
    /// A retry of the same key replays no-work even if work arrives later.
    async fn record_no_work(
        &self,
        request: NoWorkLeaseRequest,
    ) -> Result<TryClaimReceipt, StoreError>;
}

/// Authoritative scheduler queue port. Claims/no-work receipts atomically
/// commit the opaque cursor advancement returned with a page.
#[async_trait]
pub trait RunnableAttemptRepository: Send + Sync {
    /// Loads one bounded page of runnable attempts after the opaque scan cursor.
    async fn scan_runnable(
        &self,
        request: RunnableScanRequest,
    ) -> Result<RunnableScanPage, StoreError>;
}
